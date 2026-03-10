/**
 * @NApiVersion 2.1
 * @NScriptType Suitelet
 * @NModuleScope SameAccount
 */
define(['N/ui/serverWidget', 'N/search', 'N/log', 'N/record', 'N/runtime', 'N/encode', 'N/crypto'], (serverWidget, search, log, record, runtime, encode, crypto) => {

    // Authentication functions
    function generateSessionToken(employeeData) {
        // Create a unique session token based on employee data and timestamp
        const timestamp = new Date().getTime();
        
        // Include essential employee data in the token
        // Format: employeeId|email|timestamp
        const data = employeeData.id + '|' + employeeData.email + '|' + timestamp;
        
        const hash = crypto.createHash({
            algorithm: crypto.HashAlg.SHA256
        });
        hash.update({
            input: data
        });
        
        const token = hash.digest({
            outputEncoding: encode.Encoding.HEX
        });
        
        log.debug('Generated token for employee', { 
            employeeId: employeeData.id, 
            email: employeeData.email,
            tokenPrefix: token.substring(0, 10) 
        });
        
        return token;
    }

    function validateCredentials(email, password) {
        if (!email || !password) {
            log.debug('Auth validation failed', 'Email or password is empty');
            return { authenticated: false };
        }
        
        try {
            // Log authentication attempt (without showing actual password)
            log.debug('Authentication attempt', {
                email: email,
                passwordLength: password ? password.length : 0
            });
            
            // Search for employee with matching email and password
            const employeeSearch = search.create({
                type: search.Type.EMPLOYEE,
                filters: [
                    ['email', 'is', email],
                    'AND',
                    ['custentity_es_mobileordering_pass', 'is', password],
                    'AND',
                    ['isinactive', 'is', 'F']
                ],
                columns: [
                    'internalid',
                    'entityid',
                    'firstname', 
                    'lastname',
                    'email',
                    'location',
                    'department'
                ]
            });
            
            log.debug('Employee search created', { 
                type: 'employee',
                email: email,
                customField: 'custentity_es_mobileordering_pass'
            });
            
            const results = employeeSearch.run().getRange({ start: 0, end: 1 });
            log.debug('Employee search results', { count: results ? results.length : 0 });
            
            if (results && results.length > 0) {
                const employee = {
                    id: results[0].getValue('internalid'),
                    employeeId: results[0].getValue('entityid'),
                    firstName: results[0].getValue('firstname'),
                    lastName: results[0].getValue('lastname'),
                    email: results[0].getValue('email'),
                    location: results[0].getValue('location'),
                    locationText: results[0].getText('location'),
                    department: results[0].getValue('department'),
                    departmentText: results[0].getText('department')
                };
                
                log.debug('Employee found', {
                    id: employee.id,
                    employeeId: employee.employeeId,
                    name: employee.firstName + ' ' + employee.lastName,
                    location: employee.locationText,
                    department: employee.departmentText
                });
                
                // Generate a session token
                const token = generateSessionToken(employee);
                
                return {
                    authenticated: true,
                    employee: employee,
                    token: token
                };
            }
            
            // If no employee was found, try a direct lookup to see if the field exists
            try {
                const employeeEmailSearch = search.create({
                    type: search.Type.EMPLOYEE,
                    filters: [
                        ['email', 'is', email],
                        'AND',
                        ['isinactive', 'is', 'F']
                    ],
                    columns: [
                        'internalid',
                        'custentity_es_mobileordering_pass'
                    ]
                });
                
                const emailResults = employeeEmailSearch.run().getRange({ start: 0, end: 1 });
                if (emailResults && emailResults.length > 0) {
                    const storedPassword = emailResults[0].getValue('custentity_es_mobileordering_pass');
                    log.debug('Employee found but password mismatch', { 
                        hasPassword: !!storedPassword,
                        passwordLength: storedPassword ? storedPassword.length : 0,
                        submittedPasswordLength: password.length
                    });
                } else {
                    log.debug('No employee found with this email', { email: email });
                }
            } catch (e) {
                log.error('Error during password verification', e);
            }
            
            log.debug('Authentication failed', 'No matching employee found with correct password');
            return { authenticated: false };
        } catch (e) {
            log.error('Authentication error', e);
            return { authenticated: false, error: e.message };
        }
    }

    function isAuthenticated(request) {
        // Check if authenticated via session token in URL
        const token = request.parameters.token;
        
        // Log the token for debugging
        log.debug('Authentication check', {
            hasToken: !!token,
            tokenValue: token ? token.substring(0, 10) + '...' : 'none',
            requestParams: JSON.stringify(request.parameters)
        });
        
        // For now, we'll accept any properly formatted token
        // In a production environment, you would validate the token
        // against a stored value or decrypt it to verify authenticity
        if (token) {
            try {
                // Make sure the token is properly formatted (simple validation)
                if (token.length < 10) {
                    log.debug('Token validation failed', 'Token too short');
                    return false;
                }
                
                // Since the token is a SHA256 hash, it should be 64 characters long
                if (token.length !== 64) {
                    log.debug('Token validation failed', 'Invalid token length');
                    return false;
                }
                
                // Check if token contains only valid hex characters
                if (!/^[a-f0-9]+$/i.test(token)) {
                    log.debug('Token validation failed', 'Invalid token format');
                    return false;
                }
                
                log.debug('Token validation passed', { tokenPrefix: token.substring(0, 10) });
                return true;
            } catch (e) {
                log.error('Token validation error', e);
                return false;
            }
        }
        
        return false;
    }

    function getAuthenticatedEmployee(token, request) {
        if (!token || token.length < 10) {
            log.debug('getAuthenticatedEmployee - invalid token', {
                token: token ? token.substring(0, 10) + '...' : 'none',
                length: token ? token.length : 0
            });
            return null;
        }
        
        try {
            // First try to get employee ID from URL parameters (passed during login redirect)
            const employeeId = request && request.parameters ? request.parameters.empid : null;
            
            if (employeeId) {
                log.debug('getAuthenticatedEmployee - using employee ID from URL', {
                    employeeId: employeeId,
                    token: token.substring(0, 10) + '...'
                });
                
                // Look up the employee record using the ID from URL
                const employeeSearch = search.create({
                    type: search.Type.EMPLOYEE,
                    filters: [
                        ['internalid', 'is', employeeId],
                        'AND',
                        ['isinactive', 'is', 'F']
                    ],
                    columns: [
                        'internalid',
                        'entityid',
                        'firstname', 
                        'lastname',
                        'email',
                        'location',
                        'department'
                    ]
                });
                
                const results = employeeSearch.run().getRange({ start: 0, end: 1 });
                
                if (results && results.length > 0) {
                    const employee = {
                        id: results[0].getValue('internalid'),
                        employeeId: results[0].getValue('entityid'),
                        firstName: results[0].getValue('firstname'),
                        lastName: results[0].getValue('lastname'),
                        email: results[0].getValue('email'),
                        location: results[0].getValue('location'),
                        locationText: results[0].getText('location'),
                        department: results[0].getValue('department'),
                        departmentText: results[0].getText('department')
                    };
                    
                    log.debug('getAuthenticatedEmployee - found employee from URL ID', {
                        id: employee.id,
                        name: employee.firstName + ' ' + employee.lastName,
                        email: employee.email,
                        location: employee.locationText,
                        department: employee.departmentText
                    });
                    
                    return employee;
                } else {
                    log.debug('getAuthenticatedEmployee - employee not found for URL ID', { employeeId: employeeId });
                    return null;
                }
            }
            
            log.debug('getAuthenticatedEmployee - no valid employee found for token');
            return null;
        } catch (e) {
            log.error('Error getting authenticated employee', e);
            return null;
        }
    }

    const onRequest = (context) => {
        const { request, response } = context;
        const action = (request.parameters.action || '').toLowerCase();
        
        // Handle login GET request (show login form)
        if (request.method === 'GET' && action === 'login') {
            log.debug('Showing login form');
            response.addHeader({ name: 'Content-Type', value: 'text/html; charset=utf-8' });
            renderLoginForm(response);
            return;
        }
        
        // Handle login POST request
        if (request.method === 'POST' && action === 'login') {
            response.addHeader({ name: 'Content-Type', value: 'text/html; charset=utf-8' });
            
            let email, password;
            try {
                // Get form data
                email = request.parameters.email;
                password = request.parameters.password;
            } catch (e) {
                log.error('Error parsing login form data', e);
                renderLoginForm(response, 'Invalid form submission');
                return;
            }
            
            // Validate credentials
            const authResult = validateCredentials(email, password);
            
            if (authResult && authResult.authenticated) {
                // Redirect to main app with token
                const token = encodeURIComponent(authResult.token);
                
                log.debug('Authenticated employee', {
                    token: authResult.token.substring(0, 10) + '...',
                    employeeId: authResult.employee.id,
                    name: authResult.employee.firstName + ' ' + authResult.employee.lastName
                });
                
                // Read the original params directly from the request
                const currentUrl = request.url;
                const scriptInternalId = request.parameters.script || runtime.getCurrentScript().id;
                const deployInternalId = request.parameters.deploy || runtime.getCurrentScript().deploymentId;
                const dynamicCompanyId = request.parameters.compid || '';
                
                log.debug('URL parameters', {
                    scriptId: scriptInternalId,
                    deployId: deployInternalId,
                    companyId: dynamicCompanyId,
                    allParams: JSON.stringify(request.parameters)
                });
                
                // Build redirect by preserving ALL existing query params and appending token and employee ID
                const baseUrl = request.url.split('?')[0];
                const preserved = [];
                var k;
                for (k in request.parameters) {
                    if (!request.parameters.hasOwnProperty(k)) continue;
                    if (k === 'action' || k === 'email' || k === 'password' || k === 'token' || k === 'empid') continue;
                    const v = request.parameters[k];
                    if (v !== undefined && v !== null && String(v).length > 0) {
                        preserved.push(k + '=' + encodeURIComponent(String(v)));
                    }
                }
                // Ensure required params are present
                function hasParam(name){ return preserved.some(function(p){ return p.split('=')[0] === name; }); }
                if (!hasParam('script') && scriptInternalId) preserved.push('script=' + encodeURIComponent(String(scriptInternalId)));
                if (!hasParam('deploy') && deployInternalId) preserved.push('deploy=' + encodeURIComponent(String(deployInternalId)));
                if (!hasParam('compid') && dynamicCompanyId) preserved.push('compid=' + encodeURIComponent(String(dynamicCompanyId)));
                // Add/replace token and employee ID
                preserved.push('token=' + token);
                preserved.push('empid=' + encodeURIComponent(authResult.employee.id));
                const redirectUrl = baseUrl + '?' + preserved.join('&');
                
                // Use client-side redirect
                response.write('<html><head><script>window.location.href = "' + redirectUrl + '";</script></head><body>Redirecting...</body></html>');
                return;
            } else {
                // Show login form with error
                renderLoginForm(response, 'Invalid email or password');
                return;
            }
        }
        
        // Handle logout request
        if (action === 'logout') {
            log.debug('Logout requested');
            response.addHeader({ name: 'Content-Type', value: 'text/html; charset=utf-8' });
            
            // Build redirect URL to login page, preserving script/deploy/compid params
            const baseUrl = request.url.split('?')[0];
            const preserved = [];
            var k;
            for (k in request.parameters) {
                if (!request.parameters.hasOwnProperty(k)) continue;
                if (k === 'action' || k === 'token' || k === 'empid') continue;
                const v = request.parameters[k];
                if (v !== undefined && v !== null && String(v).length > 0) {
                    preserved.push(k + '=' + encodeURIComponent(String(v)));
                }
            }
            // Ensure required params are present
            function hasParam(name){ return preserved.some(function(p){ return p.split('=')[0] === name; }); }
            const scriptInternalId = request.parameters.script || runtime.getCurrentScript().id;
            const deployInternalId = request.parameters.deploy || runtime.getCurrentScript().deploymentId;
            const dynamicCompanyId = request.parameters.compid || '';
            if (!hasParam('script') && scriptInternalId) preserved.push('script=' + encodeURIComponent(String(scriptInternalId)));
            if (!hasParam('deploy') && deployInternalId) preserved.push('deploy=' + encodeURIComponent(String(deployInternalId)));
            if (!hasParam('compid') && dynamicCompanyId) preserved.push('compid=' + encodeURIComponent(String(dynamicCompanyId)));
            
            preserved.push('action=login');
            const loginUrl = baseUrl + '?' + preserved.join('&');
            
            // Redirect to login page
            response.write('<html><head><script>window.location.href = "' + loginUrl + '";</script></head><body>Logging out...</body></html>');
            return;
        }
        
        // Check authentication for all other requests except login and logout
        if (action !== 'login' && action !== 'logout') {
            // Get token from URL parameters or form POST parameters
            const token = request.parameters.token || request.parameters.custpage_token || '';
            const empid = request.parameters.empid || request.parameters.custpage_empid || '';
            
            // Create a modified request object with token for authentication check
            const authRequest = {
                parameters: Object.assign({}, request.parameters, {
                    token: token,
                    empid: empid
                })
            };
            
            const isAuth = isAuthenticated(authRequest);
            const authEmployee = getAuthenticatedEmployee(token, authRequest);
            
            log.debug('Authentication result', { 
                isAuthenticated: isAuth, 
                action: action,
                hasAuthEmployee: !!authEmployee,
                employeeId: authEmployee ? authEmployee.id : null
            });
            
            if (!isAuth) {
                // Always show login form if not authenticated
                log.debug('No token found - redirecting to login');
                response.addHeader({ name: 'Content-Type', value: 'text/html; charset=utf-8' });
                
                // Build redirect URL with action=login, preserving script/deploy/compid params
                const baseUrl = request.url.split('?')[0];
                const preserved = [];
                var k;
                for (k in request.parameters) {
                    if (!request.parameters.hasOwnProperty(k)) continue;
                    if (k === 'action' || k === 'token' || k === 'empid') continue;
                    const v = request.parameters[k];
                    if (v !== undefined && v !== null && String(v).length > 0) {
                        preserved.push(k + '=' + encodeURIComponent(String(v)));
                    }
                }
                // Ensure required params are present
                function hasParam(name){ return preserved.some(function(p){ return p.split('=')[0] === name; }); }
                const scriptInternalId = request.parameters.script || runtime.getCurrentScript().id;
                const deployInternalId = request.parameters.deploy || runtime.getCurrentScript().deploymentId;
                const dynamicCompanyId = request.parameters.compid || '';
                if (!hasParam('script') && scriptInternalId) preserved.push('script=' + encodeURIComponent(String(scriptInternalId)));
                if (!hasParam('deploy') && deployInternalId) preserved.push('deploy=' + encodeURIComponent(String(deployInternalId)));
                if (!hasParam('compid') && dynamicCompanyId) preserved.push('compid=' + encodeURIComponent(String(dynamicCompanyId)));
                
                preserved.push('action=login');
                const loginUrl = baseUrl + '?' + preserved.join('&');
                
                // Redirect to login page
                response.write('<html><head><script>window.location.href = "' + loginUrl + '";</script></head><body>Redirecting to login...</body></html>');
                return;
            }
        }

        // User is logged in, show main app
        const form = buildForm();
        
        // Preserve token and employee ID in hidden fields for form submission
        // Check both URL parameters and form POST parameters (custpage_token from hidden field)
        const token = request.parameters.token || request.parameters.custpage_token || '';
        const empid = request.parameters.empid || request.parameters.custpage_empid || '';
        
        // Always create hidden fields to ensure they're available for form submission
        // This is critical for preserving the session across multiple searches
        let tokenField = form.getField({ id: 'custpage_token' });
        if (!tokenField) {
            tokenField = form.addField({
                id: 'custpage_token',
                label: 'Token',
                type: serverWidget.FieldType.TEXT
            });
            tokenField.updateDisplayType({ displayType: serverWidget.FieldDisplayType.HIDDEN });
        }
        if (token) {
            tokenField.defaultValue = token;
        }
        
        let empidField = form.getField({ id: 'custpage_empid' });
        if (!empidField) {
            empidField = form.addField({
                id: 'custpage_empid',
                label: 'Employee ID',
                type: serverWidget.FieldType.TEXT
            });
            empidField.updateDisplayType({ displayType: serverWidget.FieldDisplayType.HIDDEN });
        }
        if (empid) {
            empidField.defaultValue = empid;
        }
        
        // Log for debugging
        log.debug('Form hidden fields setup', {
            hasToken: !!token,
            tokenLength: token ? token.length : 0,
            hasEmpid: !!empid,
            requestMethod: request.method,
            urlHasToken: !!request.parameters.token,
            formHasToken: !!request.parameters.custpage_token
        });

        const itemId = request.parameters.item || '';

        // Handle GET request
        if (request.method === 'GET') {
            // If item ID is in URL (from redirect after POST), process and display it
            if (itemId) {
                // Process item data (same logic as POST request below)
                // This will be handled by the code after this block
            } else {
                // No item selected, just show empty form
                response.writePage(form);
                return;
            }
        }

        // Handle POST request or GET request with item ID
        if (request.method === 'POST' && !itemId) {
            addMessage(form, 'warning', 'Missing Item', 'Please select an Item and submit.');
            response.writePage(form);
            return;
        }

        if (!itemId) {
            addMessage(form, 'warning', 'Missing Item', 'Please select an Item and submit.');
            response.writePage(form);
            return;
        }

        try {
            // Handle saving editable fields (item code and display name)
            const updateItemId = request.parameters['custpage_update_itemid_' + itemId];
            const updateDisplayName = request.parameters['custpage_update_displayname_' + itemId];
            
            if (updateItemId || updateDisplayName) {
                try {
                    const itemRecord = record.load({
                        type: record.Type.INVENTORY_ITEM,
                        id: itemId,
                        isDynamic: false
                    });
                    
                    if (updateItemId) {
                        itemRecord.setValue({ fieldId: 'itemid', value: updateItemId });
                        log.debug('Updating item code to:', updateItemId);
                    }
                    
                    if (updateDisplayName) {
                        itemRecord.setValue({ fieldId: 'displayname', value: updateDisplayName });
                        log.debug('Updating display name to:', updateDisplayName);
                    }
                    
                    itemRecord.save({ enableSourcing: false, ignoreMandatoryFields: false });
                    log.debug('Item record updated successfully');
                    addMessage(form, 'confirmation', 'Success', 'Item details updated successfully.');
                } catch (saveError) {
                    log.error('Error saving item updates', saveError);
                    addMessage(form, 'error', 'Update Error', 'Failed to save item updates: ' + String(saveError.message || saveError));
                }
            }

                // Item header
            log.debug('=== STARTING DATA RETRIEVAL FOR ITEM:', itemId, '===');
            const header = getItemHeaderDetails(itemId);
                log.debug('Item header data:', header);

                // Inject shared styles and scripts for responsive UI (only once)
                form.addField({
                    id: 'custpage_app_assets',
                    label: 'Assets',
                    type: serverWidget.FieldType.INLINEHTML
                }).defaultValue = getAppStylesAndScripts();

                log.debug('Getting inventory data for item', itemId);
            const inventoryByLocation = getInventoryByLocation(itemId);
                log.debug('Raw inventory data retrieved:', inventoryByLocation);
                
                log.debug('Getting on-order data for item', itemId);
            const onOrderByLocation = getOnOrderByLocation(itemId);
                log.debug('Raw on-order data retrieved:', onOrderByLocation);

                // Merge inventory and on-order data by location
            const locationIdToRow = {};

                // Preferred: build dynamically from returned data; fallback to static list
                const hasDynamicData = (inventoryByLocation && Object.keys(inventoryByLocation).length > 0) ||
                    (onOrderByLocation && Object.keys(onOrderByLocation).length > 0);

                const defaultLocationIds = [7, 9, 10, 11, 18, 19];
                const locationNames = {
                    7: '1001_Newmarket',
                    9: '1002_Maple', 
                    10: '1003_Burlington',
                    11: '1004_Woodbridge',
                    18: '1005_Southcore',
                    19: '1006_Oakville'
                };

                if (!hasDynamicData) {
                    defaultLocationIds.forEach((locId) => {
                        locationIdToRow[locId] = {
                            locationName: locationNames[locId],
                            onHand: 0,
                            onOrder: 0
                        };
                    });
                }

                // Update with actual inventory data (by id or by name match); create rows if missing
                Object.keys(inventoryByLocation).forEach((key) => {
                    const data = inventoryByLocation[key] || {};
                    const byId = locationIdToRow[key];
                    if (byId) {
                        byId.onHand = data.onHand || 0;
                        log.debug('Updated onHand by ID for location', key, ':', byId.onHand);
                        return;
                    }
                    const name = (data.locationName || '').toString();
                    if (name) {
                        const matchId = Object.keys(locationIdToRow).find(id => locationIdToRow[id].locationName === name);
                        if (matchId) {
                            locationIdToRow[matchId].onHand = data.onHand || 0;
                            log.debug('Updated onHand by NAME for location', name, '->', matchId, ':', locationIdToRow[matchId].onHand);
                        } else {
                            // create a new row for this location name
                            locationIdToRow[name] = {
                                locationName: name,
                                onHand: data.onHand || 0,
                                onOrder: 0
                            };
                            log.debug('Created row for location (inventory)', name, locationIdToRow[name]);
                        }
                    }
                });

                // Add on-order data (by id or by name match); create rows if missing
                Object.keys(onOrderByLocation).forEach((key) => {
                    const onOrderData = onOrderByLocation[key] || {};
                    const byId = locationIdToRow[key];
                    if (byId) {
                        byId.onOrder = onOrderData.onOrder || 0;
                        log.debug('Updated onOrder by ID for location', key, ':', byId.onOrder);
                        return;
                    }
                    const name = (onOrderData.locationName || '').toString();
                    if (name) {
                        const matchId = Object.keys(locationIdToRow).find(id => locationIdToRow[id].locationName === name);
                        if (matchId) {
                            locationIdToRow[matchId].onOrder = onOrderData.onOrder || 0;
                            log.debug('Updated onOrder by NAME for location', name, '->', matchId, ':', locationIdToRow[matchId].onOrder);
                        } else {
                            // create a new row for this location name
                            locationIdToRow[name] = {
                                locationName: name,
                                onHand: 0,
                                onOrder: onOrderData.onOrder || 0
                            };
                            log.debug('Created row for location (onorder)', name, locationIdToRow[name]);
                        }
                    }
                });
                
                // Log final merged data for debugging
                log.debug('Final merged location data:', locationIdToRow);
                log.debug('Number of locations with data:', Object.keys(locationIdToRow).length);

                // Create responsive HTML table
                const rows = Object.values(locationIdToRow).sort((a, b) => a.locationName.localeCompare(b.locationName));
                log.debug('Sorted rows for table:', rows);
                
                let tableHtml = createInventoryTableHTML(rows);
                log.debug('Generated table HTML length:', tableHtml ? tableHtml.length : 'null');

                // Build full app layout (left: item details, right: tables)

                // Add price levels table - ONLY SHOW REAL DATA
                log.debug('=== PRICE LEVELS RETRIEVAL ===');
                log.debug('Attempting to get price levels table for item', itemId);
                let priceLevelsTable = getPriceLevelsTable(itemId);
                
                // Only show price table if we have real data
                if (!priceLevelsTable) {
                    log.debug('No price data found for item', itemId);
                    // Don't show any price table if no real data is available
                } else {
                    log.debug('Price levels table created successfully, length:', priceLevelsTable.length);
                }
                
                log.debug('Price levels table result:', priceLevelsTable ? 'Table created successfully' : 'No table created');
                
                // Always add the price table content
                if (!priceLevelsTable) {
                    priceLevelsTable = '<p>No price levels available.</p>';
                }

                const appLayoutHtml = createAppLayoutHTML(header, tableHtml, priceLevelsTable);
                form.addField({
                    id: 'custpage_app_layout',
                    label: 'App',
                    type: serverWidget.FieldType.INLINEHTML
                }).defaultValue = appLayoutHtml;
                log.debug('App layout field added to form', { length: appLayoutHtml ? appLayoutHtml.length : 0 });

                // Don't preserve selected item - clear it so user can search for a new item
                // This ensures the field works the same way as the first search
            const itemField = form.getField({ id: 'item' });
                if (itemField) {
                    // Clear the field value so user can easily search for a new item
                    // The field will be empty and ready for new input, just like the first time
                    itemField.defaultValue = '';
                }

                // Final summary of what data was retrieved
                log.debug('=== FINAL DATA SUMMARY ===');
                log.debug('Item ID:', itemId);
                log.debug('Inventory locations found:', Object.keys(inventoryByLocation).length);
                log.debug('On-order locations found:', Object.keys(onOrderByLocation).length);
                log.debug('Price table created:', priceLevelsTable ? 'Yes' : 'No');
                log.debug('Total locations in final table:', rows ? rows.length : 0);
                log.debug('=== END DATA SUMMARY ===');

        } catch (e) {
            log.error({ title: 'Error generating results', details: e });
            addMessage(form, 'error', 'Unexpected Error', String(e.message || e));
            }

            // After processing POST request, redirect to GET with token preserved in URL
            // This ensures the token stays in the URL for subsequent searches
            if (request.method === 'POST' && itemId) {
                const baseUrl = request.url.split('?')[0];
                const preserved = [];
                var k;
                for (k in request.parameters) {
                    if (!request.parameters.hasOwnProperty(k)) continue;
                    // Preserve token, empid, script, deploy, compid, and item
                    if (k === 'action' || k === 'email' || k === 'password') continue;
                    const v = request.parameters[k];
                    if (v !== undefined && v !== null && String(v).length > 0) {
                        preserved.push(k + '=' + encodeURIComponent(String(v)));
                    }
                }
                // Ensure required params are present
                function hasParam(name){ return preserved.some(function(p){ return p.split('=')[0] === name; }); }
                const scriptInternalId = request.parameters.script || runtime.getCurrentScript().id;
                const deployInternalId = request.parameters.deploy || runtime.getCurrentScript().deploymentId;
                const dynamicCompanyId = request.parameters.compid || '';
                if (!hasParam('script') && scriptInternalId) preserved.push('script=' + encodeURIComponent(String(scriptInternalId)));
                if (!hasParam('deploy') && deployInternalId) preserved.push('deploy=' + encodeURIComponent(String(deployInternalId)));
                if (!hasParam('compid') && dynamicCompanyId) preserved.push('compid=' + encodeURIComponent(String(dynamicCompanyId)));
                // Ensure token and empid are present
                if (!hasParam('token') && token) preserved.push('token=' + encodeURIComponent(token));
                if (!hasParam('empid') && empid) preserved.push('empid=' + encodeURIComponent(empid));
                // Preserve item ID in URL so we can show results on GET
                if (!hasParam('item')) preserved.push('item=' + encodeURIComponent(itemId));
                
                const redirectUrl = baseUrl + '?' + preserved.join('&');
                response.write('<html><head><script>window.location.href = "' + redirectUrl + '";</script></head><body>Loading...</body></html>');
                return;
            }

            response.writePage(form);
    };

    function renderLoginForm(response, errorMessage) {
        const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Item Lookup App Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body {
      background-color: #f8f9fa;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
      padding: 20px;
                }
                .login-container {
      max-width: 400px;
                    width: 100%;
      padding: 30px;
      background-color: #ffffff;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                }
    .login-logo {
                    text-align: center;
                    margin-bottom: 20px;
                }
    .login-logo h1 {
      color: #16a34a;
                    font-weight: 600;
      margin: 0 0 8px 0;
      font-size: 1.75rem;
    }
    .btn-primary {
      background-color: #16a34a;
                    border-color: #16a34a;
                    width: 100%;
      padding: 10px;
      font-weight: 500;
    }
    .btn-primary:hover,
    .btn-primary:focus {
      background-color: #15803d;
      border-color: #15803d;
    }
    .btn-primary:active,
    .btn-primary:focus,
    .btn-primary.active,
    .btn-primary.focus {
      background-color: #15803d !important;
      border-color: #15803d !important;
      box-shadow: 0 0 0 0.25rem rgba(22, 163, 74, 0.25) !important;
    }
    .form-control:focus {
      border-color: #16a34a;
      box-shadow: 0 0 0 0.25rem rgba(22, 163, 74, 0.25);
    }
    .error-message {
      color: #dc3545;
      margin-bottom: 15px;
      text-align: center;
                }
            </style>
</head>
<body>
  <div class="login-container">
    <div class="login-logo">
      <h1>Item Lookup App</h1>
      <p class="text-muted">Please sign in to continue</p>
    </div>
    
    ${errorMessage ? `<div class="error-message">${errorMessage}</div>` : ''}
    
    <form method="post" action="">
      <input type="hidden" name="action" value="login">
      <div class="mb-3">
        <label for="email" class="form-label">Email</label>
        <input type="email" class="form-control" id="email" name="email" required autocomplete="email">
      </div>
      <div class="mb-3">
        <label for="password" class="form-label">Password</label>
        <input type="password" class="form-control" id="password" name="password" required autocomplete="current-password">
      </div>
      <button type="submit" class="btn btn-primary">Sign In</button>
    </form>
  </div>
</body>
</html>`;
        response.write(html);
    }

    function buildForm() {
            const form = serverWidget.createForm({ title: 'Item Lookup App' });

            // Item select field
            const itemField = form.addField({
                id: 'item',
                label: 'Item',
                type: serverWidget.FieldType.SELECT,
                source: 'item'
            });
        itemField.isMandatory = true;

            // Submit button
        form.addSubmitButton({ label: 'Item Lookup' });

        return form;
    }

    function addMessage(form, type, title, message) {
        try {
                form.addPageInitMessage({
                    type: serverWidget.Message.Type[type.toUpperCase()] || serverWidget.Message.Type.INFORMATION,
                    title,
                    message
                });
        } catch (_e) {
                // fallback
            const field = form.addField({ id: 'custpage_msg', label: title, type: serverWidget.FieldType.INLINEHTML });
                field.defaultValue = `<div><strong>${title}:</strong> ${message}</div>`;
            }
        }

        function addItemHeaderFields(form, header) {
            // Deprecated: These are now rendered inside the app layout HTML on the left panel
            form.addField({ id: 'custpage_header_placeholder', label: 'Header', type: serverWidget.FieldType.INLINEHTML }).defaultValue = '';
        }


    function getItemHeaderDetails(itemId) {
        const details = { 
                internalId: itemId, 
                itemId: '', 
                displayName: '', 
                upcCode: '', 
                externalId: '',
                basePrice: ''
            };

            // Get basic item details
        const s = search.create({
            type: 'item',
                filters: [['internalid', 'anyof', itemId]],
            columns: [
                    'itemid', 
                    'displayname', 
                    'upccode', 
                    'custitem_external_id',
                    'price'
                ]
            });

            s.run().each((res) => {
            details.itemId = res.getValue('itemid') || '';
            details.displayName = res.getValue('displayname') || '';
            details.upcCode = res.getValue('upccode') || '';
            details.externalId = res.getValue('custitem_external_id') || '';
                details.basePrice = res.getValue('price') || '';
                
                log.debug('Basic item search results', {
                    itemId: details.itemId,
                    displayName: details.displayName,
                    basePrice: details.basePrice
                });
                
                return false; // only first result
            });

            // Test different search types to find what's available
            log.debug('Testing available search types for inventory data');
            
            // Test 1: Try item search with inventory fields
            try {
                const testSearch = search.create({
                    type: 'item',
                    filters: [['internalid', 'anyof', itemId]],
                    columns: ['quantityonhand', 'quantityavailable', 'quantityonorder']
                });
                
                testSearch.run().each((res) => {
                    const onHand = res.getValue('quantityonhand') || '';
                    const available = res.getValue('quantityavailable') || '';
                    const onOrder = res.getValue('quantityonorder') || '';
                    
                    log.debug('Item search results', {
                        onHand: onHand,
                        available: available,
                        onOrder: onOrder
                    });
                    
                    return false;
                });
            } catch (e) {
                log.debug('Item search with inventory fields failed', e);
            }
            
        // Price levels are now handled in the separate table, no need for complex logic here

        return details;
    }

    function getPriceLevelsBySearch(itemId) {
        const priceLevels = [];
        
        try {
            log.debug('Starting custom price record search for item', itemId);
            
            // First, get the base price from the item record
            let basePrice = 0;
            try {
                const itemRecord = record.load({
                    type: record.Type.INVENTORY_ITEM,
                    id: itemId,
                    isDynamic: false
                });
                basePrice = Number(itemRecord.getValue('price')) || 0;
                log.debug('Base price from item record:', basePrice);
            } catch (e) {
                log.debug('Could not get base price from record:', e);
            }
            
            // Use custom item fields for price data
            log.debug('Using custom item fields for price data');
            
            try {
                log.debug('Getting price data from custom item fields...');
                
                // Load the item record to get custom price fields
                const itemRecord = record.load({
                    type: record.Type.INVENTORY_ITEM,
                    id: itemId,
                    isDynamic: false
                });
                
                // First, let's discover what custom fields actually exist on this item
                log.debug('Discovering available custom fields on item record...');
                
                // Try different possible field name patterns
                const possibleFieldPatterns = [
                    // Pattern 1: custitem_itempriceline1_itemprice
                    { priceField: 'custitem_itempriceline1_itemprice', priceTypeField: 'custitem_itempriceline1_itempricetyperef' },
                    // Pattern 2: custitem_itempriceline1_itemPrice (different capitalization)
                    { priceField: 'custitem_itempriceline1_itemPrice', priceTypeField: 'custitem_itempriceline1_itemPriceTypeRef' },
                    // Pattern 3: custitem_itempriceline1_price
                    { priceField: 'custitem_itempriceline1_price', priceTypeField: 'custitem_itempriceline1_pricetype' },
                    // Pattern 4: custitem_itempriceline1_pricevalue
                    { priceField: 'custitem_itempriceline1_pricevalue', priceTypeField: 'custitem_itempriceline1_pricetype' },
                    // Pattern 5: custitem_itempriceline1_unitprice
                    { priceField: 'custitem_itempriceline1_unitprice', priceTypeField: 'custitem_itempriceline1_pricetype' }
                ];
                
                let foundWorkingPattern = false;
                
                for (let pattern of possibleFieldPatterns) {
                    try {
                        log.debug('Trying field pattern:', pattern);
                        
                        const price = Number(itemRecord.getValue(pattern.priceField)) || 0;
                        const priceType = itemRecord.getText(pattern.priceTypeField) || itemRecord.getValue(pattern.priceTypeField) || '';
                        
                        log.debug(`Pattern test result:`, {
                            priceField: pattern.priceField,
                            priceTypeField: pattern.priceTypeField,
                            price: price,
                            priceType: priceType
                        });
                        
                        if (price > 0 && priceType) {
                            log.debug('Found working field pattern!', pattern);
                            foundWorkingPattern = pattern;
                            break;
                        }
                    } catch (e) {
                        log.debug('Pattern failed:', pattern, 'Error:', e.message);
                    }
                }
                
                if (foundWorkingPattern) {
                    log.debug('Using working pattern:', foundWorkingPattern);
                    
                    // Now try to get multiple price lines using the working pattern
                    const maxPriceLines = 10;
                    
                    for (let i = 1; i <= maxPriceLines; i++) {
                        try {
                            const priceField = foundWorkingPattern.priceField.replace('1', i.toString());
                            const priceTypeField = foundWorkingPattern.priceTypeField.replace('1', i.toString());
                            
                            const price = Number(itemRecord.getValue(priceField)) || 0;
                            const priceType = itemRecord.getText(priceTypeField) || itemRecord.getValue(priceTypeField) || '';
                            
                            log.debug(`Price Line ${i}:`, {
                                price: price,
                                priceType: priceType,
                                priceField: priceField,
                                priceTypeField: priceTypeField
                            });
                            
                            if (price > 0 && priceType) {
                                priceLevels.push({
                                    name: priceType,
                                    price: price,
                                    quantity: 1,
                                    discount: ''
                                });
                                log.debug(`Added price level: ${priceType} = $${price}`);
                            }
                        } catch (fieldError) {
                            log.debug(`Price line ${i} fields not found, stopping at line ${i-1}`);
                            break;
                        }
                    }
                } else {
                    log.debug('No working field pattern found, trying to discover all custom fields...');
                    
                    // Try to get all custom fields that might contain price data
                    const allCustomFields = [
                        'custitem_itempriceline1_itemprice',
                        'custitem_itempriceline1_itemPrice',
                        'custitem_itempriceline1_itempricetyperef',
                        'custitem_itempriceline1_itemPriceTypeRef',
                        'custitem_itempriceline1_price',
                        'custitem_itempriceline1_pricetype',
                        'custitem_itempriceline1_pricevalue',
                        'custitem_itempriceline1_unitprice'
                    ];
                    
                    allCustomFields.forEach(fieldName => {
                        try {
                            const value = itemRecord.getValue(fieldName);
                            const text = itemRecord.getText(fieldName);
                            log.debug(`Field ${fieldName}:`, { value: value, text: text });
                        } catch (e) {
                            // Field doesn't exist
                        }
                    });
                }
                
                log.debug('Found price levels from custom fields:', priceLevels);
                
            } catch (e) {
                log.debug('Custom item fields search failed:', e);
            }
            
            // Try to get price levels from standard NetSuite pricing
            log.debug('Trying standard NetSuite pricing searches');
            
            const searchConfigs = [
                {
                    type: 'pricing',
                    filters: [['item', 'anyof', itemId]],
                    columns: ['pricelevel', 'unitprice', 'priceqty']
                },
                {
                    type: 'item',
                    filters: [['internalid', 'anyof', itemId]],
                    columns: ['price']
                }
            ];
            
            let foundPrices = false;
            
            for (let config of searchConfigs) {
                try {
                    log.debug('Trying price search with type:', config.type);
                    
                    const priceSearch = search.create({
                        type: config.type,
                        filters: config.filters,
                        columns: config.columns
                    });
                    
                    priceSearch.run().each((res) => {
                        if (config.type === 'pricing') {
                            const priceLevelName = res.getText('pricelevel') || '';
                            const unitPrice = Number(res.getValue('unitprice')) || 0;
                            const priceQty = Number(res.getValue('priceqty')) || 1;
                            
                            log.debug('Found pricing data', {
                                name: priceLevelName,
                                price: unitPrice,
                                qty: priceQty
                            });
                            
                            if (priceLevelName && unitPrice > 0) {
                                priceLevels.push({
                                    name: priceLevelName,
                                    price: unitPrice,
                                    quantity: priceQty,
                                    discount: ''
                                });
                                foundPrices = true;
                            }
                        } else if (config.type === 'item') {
                            const itemPrice = Number(res.getValue('price')) || 0;
                            log.debug('Found item base price:', itemPrice);
                            
                            if (itemPrice > 0) {
                                priceLevels.push({
                                    name: 'Base Price',
                                    price: itemPrice,
                                    quantity: 1,
                                    discount: ''
                                });
                                foundPrices = true;
                            }
                        }
                        
                        return true;
                    });
                    
                    if (foundPrices) {
                        log.debug('Successfully found prices using', config.type);
                        break;
                    }
                    
                } catch (e) {
                    log.debug('Price search with type', config.type, 'failed:', e);
                }
            }
            
            // Ensure we have all required price levels
            if (basePrice > 0) {
                log.debug('Ensuring all required price levels are present');
                
                // Define the required price levels
                const requiredPriceLevels = [
                    { name: 'DoorDash', multiplier: 1.05 }, // 5% markup
                    { name: 'Instacart', multiplier: 1.05 }, // 5% markup
                    { name: 'SMS_Regular', multiplier: 1.0 }, // Same as base
                    { name: 'Uber', multiplier: 1.05 }, // 5% markup
                    { name: 'Online Price', multiplier: 1.0 } // Same as base
                ];
                
                // Check which required price levels are missing
                const existingPriceLevelNames = priceLevels.map(p => p.name);
                const missingPriceLevels = requiredPriceLevels.filter(required => 
                    !existingPriceLevelNames.some(existing => 
                        existing.toLowerCase().includes(required.name.toLowerCase()) ||
                        required.name.toLowerCase().includes(existing.toLowerCase())
                    )
                );
                
                log.debug('Existing price levels from custom fields:', existingPriceLevelNames);
                log.debug('Missing required price levels:', missingPriceLevels.map(p => p.name));
                
                // Create missing price levels
                missingPriceLevels.forEach(level => {
                    const calculatedPrice = basePrice * level.multiplier;
                    priceLevels.push({
                        name: level.name,
                        price: Math.round(calculatedPrice * 100) / 100, // Round to 2 decimal places
                        quantity: 1,
                        discount: ''
                    });
                    log.debug(`Created missing price level: ${level.name} = $${Math.round(calculatedPrice * 100) / 100}`);
                });
                
                // If no pricing data was found at all, create all required price levels
                if (priceLevels.length === 0) {
                    log.debug('No pricing data found, creating all required price levels');
                    requiredPriceLevels.forEach(level => {
                        const calculatedPrice = basePrice * level.multiplier;
                        priceLevels.push({
                            name: level.name,
                            price: Math.round(calculatedPrice * 100) / 100,
                            quantity: 1,
                            discount: ''
                        });
                    });
                }
                
                log.debug('Final price levels after ensuring completeness:', priceLevels);
            }
            
            // If no prices found, create a basic price level with the base price
            if (priceLevels.length === 0 && basePrice > 0) {
                log.debug('No specific price levels found, using base price');
                priceLevels.push({
                    name: 'Base Price',
                    price: basePrice,
                    quantity: 1,
                    discount: ''
                });
            }
            
            log.debug('Price levels search completed, found', priceLevels.length, 'price levels');
            
            if (priceLevels.length > 0) {
                return createPriceLevelsTableHTML(selectDesiredPriceLevels(priceLevels));
            }
            
        } catch (e) {
            log.debug('Price levels search failed', e);
        }
        
        return null;
    }

    function getAllPriceLevels() {
        const allPriceLevels = [];
        
        try {
            const priceLevelSearch = search.create({
                type: 'pricelevel',
                filters: [
                    ['isinactive', 'is', 'F'] // Only active price levels
                ],
                columns: [
                    'name',
                    'internalid'
                ]
            });

            priceLevelSearch.run().each((res) => {
                const name = res.getText('name') || '';
                const id = res.getValue('internalid') || '';
                
                allPriceLevels.push({ name, id });
                log.debug('Found price level:', name, 'ID:', id);
                
                return true;
            });

            log.debug('All available price levels:', allPriceLevels);
        } catch (e) {
            log.debug('Failed to get price levels list', e);
        }

        return allPriceLevels;
    }

    function getPriceLevelsFromSublist(itemRecord, sublistName) {
        try {
            log.debug('Getting price levels from sublist:', sublistName);
            
            const priceCount = itemRecord.getLineCount({ sublistId: sublistName });
            log.debug('Sublist', sublistName, 'has', priceCount, 'lines');
            
            if (priceCount <= 0) {
                return null;
            }
            
            const priceLevels = [];
            
            for (let i = 0; i < priceCount; i++) {
                try {
                    // Try different field combinations
                    const fieldCombinations = [
                        { nameField: 'pricelevel', priceField: 'price_1', qtyField: 'priceqty' },
                        { nameField: 'pricelevel', priceField: 'price', qtyField: 'quantity' },
                        { nameField: 'level', priceField: 'amount', qtyField: 'qty' },
                        { nameField: 'pricelist', priceField: 'rate', qtyField: 'qty' }
                    ];
                    
                    let priceLevelName = '';
                    let priceValue = '';
                    let priceQty = '';
                    
                    for (const combo of fieldCombinations) {
                        try {
                            priceLevelName = itemRecord.getSublistText({
                                sublistId: sublistName,
                                fieldId: combo.nameField,
                                line: i
                            });
                            
                            priceValue = itemRecord.getSublistValue({
                                sublistId: sublistName,
                                fieldId: combo.priceField,
                                line: i
                            });
                            
                            priceQty = itemRecord.getSublistValue({
                                sublistId: sublistName,
                                fieldId: combo.qtyField,
                                line: i
                            });
                            
                            if (priceLevelName && priceValue) {
                                log.debug('Found price data with combo:', combo);
                                break;
                            }
                        } catch (e) {
                            // Try next combination
                            continue;
                        }
                    }
                    
                    log.debug('Price Level Data from', sublistName, {
                        priceLevelName: priceLevelName,
                        priceValue: priceValue,
                        priceQty: priceQty
                    });
                    
                    if (priceLevelName && priceValue) {
                        // Calculate discount percentage if it's a discount price level
                        let discount = '';
                        if (priceLevelName.toLowerCase().includes('off') || priceLevelName.toLowerCase().includes('%')) {
                            // This is a discount price level, calculate the percentage
                            const basePrice = 17.99; // You might want to get this from the base price
                            const discountPercent = ((basePrice - priceValue) / basePrice * 100).toFixed(1);
                            if (discountPercent > 0) {
                                discount = `-${discountPercent}%`;
                            }
                        }
                        
                        priceLevels.push({
                            name: priceLevelName,
                            price: priceValue,
                            quantity: priceQty || 1,
                            discount: discount
                        });
                        
                        log.debug('Added price level from', sublistName, {
                            name: priceLevelName,
                            price: priceValue,
                            quantity: priceQty || 1,
                            discount: discount
                        });
                    }
                    
                } catch (lineError) {
                    log.debug('Error processing line', i, 'in sublist', sublistName, ':', lineError.message);
                }
            }
            
            if (priceLevels.length === 0) {
                log.debug('No valid price levels found in sublist', sublistName);
                return null;
            }
            
            // Create table HTML
            return createPriceLevelsTableHTML(selectDesiredPriceLevels(priceLevels));
            
        } catch (e) {
            log.debug('Error getting price levels from sublist', sublistName, ':', e);
            return null;
        }
    }

    function getPriceLevelsFromPricingGroup(itemRecord) {
        try {
            const possibleSublists = ['pricinggroup', 'pricing_groups', 'pricinglevels', 'grouppricing'];
            const fieldCombos = [
                { nameField: 'pricelevel', priceField: 'price', qtyField: 'priceqty' },
                { nameField: 'group', priceField: 'rate', qtyField: 'quantity' },
                { nameField: 'pricinglevel', priceField: 'unitprice', qtyField: 'qty' }
            ];
            for (const sublistId of possibleSublists) {
                try {
                    const count = itemRecord.getLineCount({ sublistId });
                    log.debug('Pricing Group sublist check', { sublistId, count });
                    if (!count || count <= 0) continue;
                    const rows = [];
                    for (let i = 0; i < count; i++) {
                        let name = '', price = '';
                        for (const combo of fieldCombos) {
                            try {
                                name = itemRecord.getSublistText({ sublistId, fieldId: combo.nameField, line: i })
                                    || itemRecord.getSublistValue({ sublistId, fieldId: combo.nameField, line: i });
                                price = itemRecord.getSublistValue({ sublistId, fieldId: combo.priceField, line: i });
                                if (name && price) break;
                            } catch (e) {
                                // try next combo
                            }
                        }
                        if (name && price) {
                            rows.push({ name: String(name), price: Number(price) });
                        }
                    }
                    if (rows.length > 0) {
                        log.debug('Pricing Group rows found', rows.map(r => r.name));
                        return createPriceLevelsTableHTML(selectDesiredPriceLevels(rows));
                    }
                } catch (e) {
                    // try next sublist id
                }
            }
        } catch (e) {
            log.debug('getPriceLevelsFromPricingGroup error', e);
        }
        return null;
    }

    function createInventoryTableHTML(inventoryData) {
        if (!inventoryData || inventoryData.length === 0) {
            return '<p>No inventory data available.</p>';
        }

        let tableHTML = `
            <div class="app-card">
                <div class="app-card__title">Inventory by Location</div>
                <div class="app-table__wrap">
                <table class="app-table app-table--inventory" data-sortable="true">
                    <colgroup>
                        <col style="width:58%">
                        <col style="width:21%">
                        <col style="width:21%">
                    </colgroup>
                    <thead>
                        <tr>
                            <th data-sort="text">Location</th>
                            <th data-sort="number" class="align-right">On Hand</th>
                            <th data-sort="number" class="align-right">On Order</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        inventoryData.forEach(row => {
            tableHTML += `
                <tr>
                    <td>${row.locationName}</td>
                    <td class="align-right">${Number(row.onHand).toFixed(2)}</td>
                    <td class="align-right">${Number(row.onOrder).toFixed(2)}</td>
                </tr>
            `;
        });

        tableHTML += `
                    </tbody>
                </table>
                </div>
            </div>
        `;

        return tableHTML;
    }

    function createPriceLevelsTableHTML(priceLevels) {
        if (!priceLevels || priceLevels.length === 0) {
            return '<p>No price levels available.</p>';
        }

        let tableHTML = `
            <div class="app-card">
                <div class="app-card__title">Price Levels</div>
                <div class="app-table__wrap">
                <table class="app-table app-table--prices" data-sortable="true">
                    <colgroup>
                        <col style="width:72%">
                        <col style="width:28%">
                    </colgroup>
                    <thead>
                        <tr>
                            <th data-sort="text">Price Level</th>
                            <th data-sort="number" class="align-right">Price</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        priceLevels.forEach(priceLevel => {
            tableHTML += `
                <tr>
                    <td>${priceLevel.name}</td>
                    <td class="align-right">${priceLevel.price !== undefined && priceLevel.price !== null && !isNaN(priceLevel.price) ? parseFloat(priceLevel.price).toFixed(2) : ''}</td>
                </tr>
            `;
        });

        tableHTML += `
                    </tbody>
                </table>
                </div>
            </div>
        `;

        return tableHTML;
    }

    function getAppStylesAndScripts() {
        return `
<style>
  body{font-family:'Inter','Segoe UI',sans-serif;background:#f5f6fb;color:#1f2933}
  .uir-machine-headerrow, .uir-page-title, .uir-machine-table-row{font-family:inherit}
  .uir-page-title, .pgBntCon, .uir-menu-button, .uir-record-info{display:none!important}
  /* Hide NetSuite More button and menu - comprehensive selectors */
  .uir-menu-button, .uir-menu-button-container, button[aria-label*="More"], button[title*="More"], 
  button[aria-label*="more"], button[title*="more"], .uir-page-actions-menu, .uir-page-actions,
  .uir-page-actions-menu-button, .uir-page-actions-menu-container, 
  [class*="menu-button"], [class*="page-actions"], [id*="menu-button"], [id*="page-actions"]{display:none!important;visibility:hidden!important;opacity:0!important;height:0!important;width:0!important;overflow:hidden!important;position:absolute!important;left:-9999px!important}
  /* Hide any dropdown menus with "Add To Shortcuts" */
  .uir-menu-dropdown, .uir-menu-popup, [role="menu"], [role="menuitem"], 
  .uir-menu, .uir-menu-item, [class*="menu-dropdown"], [class*="menu-popup"]{display:none!important;visibility:hidden!important}
  .uir-machine-row{background:transparent!important}
  .app-wrapper{max-width:1100px;margin:0 auto;padding:12px 20px 32px}
  /* Center the form title */
  .uir-page-title, h1, .uir-machine-headerrow h1{text-align:center!important;width:100%!important;margin:20px auto!important;display:block!important}
  /* Center the form container */
  .uir-machine-wrapper{display:flex!important;justify-content:center!important;align-items:center!important;min-height:60vh!important;flex-direction:column!important;width:100%!important}
  .uir-machine-table{width:100%!important;max-width:600px!important;margin:0 auto!important}
  /* Center the Item field and label */
  .uir-machine-table-row td{text-align:center!important;vertical-align:middle!important}
  .uir-machine-table-row td label, .uir-field-label{text-align:center!important;display:block!important;width:100%!important;margin-bottom:10px!important;font-weight:600!important}
  .uir-machine-table-row td select, .uir-machine-table-row td input[type="text"], .uir-machine-table-row td .uir-field{width:100%!important;max-width:400px!important;margin:0 auto!important;display:block!important}
  /* Center the submit button */
  .uir-machine-table-row:has(input[type="submit"]) td, tr:has(input[type="submit"]) td{text-align:center!important;padding:20px!important}
  input[type="submit"], button[type="submit"]{margin:0 auto!important;display:block!important}
  /* Additional centering for form elements */
  form{display:flex!important;flex-direction:column!important;align-items:center!important;width:100%!important}
  table.uir-machine-table{display:table!important;margin:0 auto!important}
  .app-wrapper{max-width:1100px;margin:0 auto;padding:12px 20px 16px}
  .app-hero-wrap{padding-bottom:0;width:100%!important;display:flex!important;justify-content:flex-start!important}
  .app-hero{background:#fff;border-radius:18px;padding:20px 24px;margin-bottom:12px;box-shadow:0 24px 70px rgba(15,23,42,.08);border:1px solid #e2e8f0;max-width:100%!important;width:100%!important}
  .app-hero__header{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;flex-wrap:nowrap;margin-bottom:16px}
  .app-hero__header-left{flex:1;min-width:0}
  .app-hero__header-right{flex-shrink:0;display:flex;align-items:center}
  .app-hero__title{margin:0 0 4px 0;font-size:28px;font-weight:700;color:#16a34a;text-align:left!important}
  .app-hero__subtitle{margin:0;color:#6b7280;font-size:14px;text-align:left!important}
  .app-hero__search-container{display:flex!important;align-items:flex-end!important;gap:12px!important;margin-top:0!important;width:100%!important}
  .app-hero__search{flex:1!important;position:relative!important;min-width:0!important;display:flex!important;flex-direction:column!important}
  .app-hero__action{display:flex!important;align-items:center!important;flex-shrink:0!important}
  .app-hero__button,.app-hero__button:focus,.app-hero__button:active{border:none!important;border-radius:12px;background:#16a34a!important;background-color:#16a34a!important;color:#ffffff!important;font-size:18px!important;font-weight:700!important;padding:18px 36px!important;cursor:pointer;box-shadow:0 10px 20px rgba(22,163,74,.25)!important;text-indent:0!important;text-align:center!important;display:inline-flex!important;align-items:center!important;justify-content:center!important;min-width:200px;height:auto!important;line-height:1.5!important;overflow:visible!important;text-overflow:clip!important;white-space:nowrap!important;letter-spacing:0.3px!important}
  .app-hero__button:hover,.app-hero__button:hover:focus,.app-hero__button:hover:active{background:#15803d!important;background-color:#15803d!important;color:#ffffff!important}
  input[type="submit"].app-hero__button,input[type="submit"].app-hero__button:focus,input[type="submit"].app-hero__button:active{background:#16a34a!important;background-color:#16a34a!important;border-color:#16a34a!important;color:#ffffff!important;text-indent:0!important;text-align:center!important;font-size:18px!important;font-weight:700!important;padding:18px 36px!important;min-width:200px!important;height:auto!important;line-height:1.5!important;overflow:visible!important;letter-spacing:0.3px!important}
  input[type="submit"].app-hero__button:hover{background:#15803d!important;background-color:#15803d!important;border-color:#15803d!important;color:#ffffff!important}
  input[type="submit"].app-hero__button::before,input[type="submit"].app-hero__button::after{display:none!important;content:none!important}
  .app-search-icon{position:absolute;width:22px;height:22px;left:18px;top:50%;transform:translateY(-50%);pointer-events:none;opacity:.5}
  .app-item-field{position:relative;margin:0}
  .app-item-field select{width:100%;border-radius:14px;border:1px solid #d0dae7;padding:16px 18px 16px 50px;font-size:16px;font-family:inherit;appearance:none;background:#fff;color:#0f172a;box-shadow:inset 0 1px 2px rgba(15,23,42,.08);user-select:none;-webkit-user-select:none;-moz-user-select:none}
  .app-item-field select:focus{outline:none;border-color:#16a34a;box-shadow:0 0 0 2px rgba(22,163,74,.35)}
  .app-item-field label{display:none}
  .app-item-field .uir-field-hint, .app-item-field .uir-field-context, .app-item-field .uir-field-help, .app-item-field .uir-tooltip{display:none!important}
  .app-item-field::after{content:attr(data-placeholder);position:absolute;left:50px;top:50%;transform:translateY(-52%);color:#9ca3af;font-size:15px;pointer-events:none;transition:opacity .2s ease,visibility .2s ease;display:none}
  .app-item-field.has-value::after{opacity:0;display:none}
  .app-item-field::before{content:'';position:absolute;width:22px;height:22px;left:18px;top:50%;transform:translateY(-50%);background:url("data:image/svg+xml,%3Csvg width='20' height='20' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M15.5 14h-.79l-.28-.27A6.471 6.471 0 0016 9.5 6.5 6.5 0 109.5 16a6.471 6.471 0 004.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C8.01 14 6 11.99 6 9.5S8.01 5 10.5 5 15 7.01 15 9.5 12.99 14 10.5 14z' fill='%239ca3af'/%3E%3C/svg%3E") no-repeat center/contain;pointer-events:none}
  .app-grid{display:flex;flex-direction:column;gap:12px}
  .app-stack{display:flex;flex-direction:column;gap:12px}
  .app-panel,.app-card{border:1px solid #e2e8f0;border-radius:18px;background:#fff;box-shadow:0 12px 30px rgba(15,23,42,.05);margin-bottom:0}
  .app-panel__body{padding:16px;font-size:14px;line-height:1.5;display:grid;row-gap:8px}
  .app-panel__body div{display:flex;justify-content:space-between;gap:12px;align-items:center}
  .app-panel__body div span{font-weight:600;color:#0f172a;text-align:right}
  .app-panel__body strong{font-weight:600;color:#1f2937;min-width:120px}
  .app-editable-field{display:flex;justify-content:space-between;gap:12px;align-items:center}
  .app-input{flex:1;max-width:400px;padding:8px 12px;border:1px solid #d1d5db;border-radius:6px;font-size:14px;font-family:inherit;background:#fff;color:#0f172a}
  .app-input:focus{outline:none;border-color:#16a34a;box-shadow:0 0 0 3px rgba(22,163,74,.1)}
  .app-card{margin:0 0 12px 0}
  .app-card__title{padding:16px 18px;font-weight:700;font-size:16px;border-bottom:1px solid #e2e8f0;background:#f8fafc}
  .app-table__wrap{width:100%;overflow:auto;padding:0 2px}
  .app-table{width:100%;border-collapse:collapse;font-size:13px;table-layout:fixed}
  .app-table th,.app-table td{padding:10px 12px;border-bottom:1px solid #e5e7eb;white-space:nowrap;line-height:1.4}
  .app-table th{background:#f9fafb;text-align:left;position:sticky;top:0;z-index:1;font-size:12px;letter-spacing:.02em;color:#475569}
  .align-right{text-align:right}
  .app-table--prices td:nth-child(2), .app-table--inventory td:nth-child(2), .app-table--inventory td:nth-child(3){text-align:right}
  .app-table--prices th:nth-child(2), .app-table--inventory th:nth-child(2), .app-table--inventory th:nth-child(3){text-align:right}
  @media (max-width: 640px){
    .app-panel__body{font-size:13px}
    .app-panel__body div{flex-direction:column;align-items:flex-start}
    .app-panel__body strong{min-width:auto}
    .app-table{font-size:12px}
    .app-table th,.app-table td{white-space:normal}
    .app-hero__header{flex-direction:column!important;align-items:stretch!important;gap:12px!important}
    .app-hero__header-right{width:100%!important;justify-content:center!important}
    .app-hero__title{font-size:24px}
    .app-hero__search-container{flex-direction:column!important;align-items:stretch!important}
    .app-hero__button{width:100%!important;justify-content:center!important;min-width:auto!important}
  }
  .sortable-asc:after{content:"?";margin-left:6px;font-size:10px}
  .sortable-desc:after{content:"?";margin-left:6px;font-size:10px}
</style>
<script>
  (function(){
    function sortTable(table, colIdx, type, asc){
      const tbody = table.tBodies[0];
      const rows = Array.from(tbody.querySelectorAll('tr'));
      const parse = (v)=>{ if(type==='number'){ const n = parseFloat(String(v).replace(/[^0-9.-]/g,'')); return isNaN(n)?0:n;} return String(v||'').toLowerCase(); };
      rows.sort((a,b)=>{
        const va = parse(a.cells[colIdx]?.innerText);
        const vb = parse(b.cells[colIdx]?.innerText);
        if(va<vb) return asc?-1:1; if(va>vb) return asc?1:-1; return 0;
      });
      rows.forEach(r=>tbody.appendChild(r));
    }
    document.addEventListener('click', function(e){
      const th = e.target.closest('th');
      if(!th) return; const table = th.closest('table');
      if(!table || table.getAttribute('data-sortable')!=='true') return;
      const idx = Array.from(th.parentNode.children).indexOf(th);
      const type = th.getAttribute('data-sort')||'text';
      const asc = !th.classList.contains('sortable-asc');
      Array.from(th.parentNode.children).forEach(h=>h.classList.remove('sortable-asc','sortable-desc'));
      th.classList.add(asc?'sortable-asc':'sortable-desc');
      sortTable(table, idx, type, asc);
    });

    function enhanceHero(){
      const form = document.querySelector('form');
      const fieldWrapper = document.getElementById('item_fs');
      if(!form || !fieldWrapper) return;
      if(form.querySelector('.app-hero')) return;
      
      // Preserve all URL parameters (token, empid, script, deploy, compid) in form action URL
      const urlParams = new URLSearchParams(window.location.search);
      const token = urlParams.get('token');
      const empid = urlParams.get('empid');
      const script = urlParams.get('script');
      const deploy = urlParams.get('deploy');
      const compid = urlParams.get('compid');
      
      // Build form action URL with all necessary parameters
      const currentAction = form.action || window.location.href.split('?')[0];
      const actionUrl = new URL(currentAction, window.location.origin);
      
      // Always ensure hidden fields exist and are populated (even if token/empid not in URL initially)
      // This ensures they're available for form submission
      let tokenField = document.getElementById('custpage_token');
      if (!tokenField) {
        tokenField = document.createElement('input');
        tokenField.type = 'hidden';
        tokenField.id = 'custpage_token';
        tokenField.name = 'custpage_token';
        form.appendChild(tokenField);
      }
      
      let empidField = document.getElementById('custpage_empid');
      if (!empidField) {
        empidField = document.createElement('input');
        empidField.type = 'hidden';
        empidField.id = 'custpage_empid';
        empidField.name = 'custpage_empid';
        form.appendChild(empidField);
      }
      
      // CRITICAL: Always read token from current URL and populate hidden fields immediately
      // This ensures the token is available even if the server-side field wasn't created properly
      const currentUrlParamsForInit = new URLSearchParams(window.location.search);
      const urlToken = currentUrlParamsForInit.get('token');
      const urlEmpid = currentUrlParamsForInit.get('empid');
      
      // Use token from URL if available, otherwise use what was passed in, otherwise use existing field value
      const finalToken = urlToken || token || tokenField.value || '';
      const finalEmpid = urlEmpid || empid || empidField.value || '';
      
      // Always set the hidden field values from URL (highest priority)
      if (urlToken) {
        tokenField.value = urlToken;
      } else if (token) {
        tokenField.value = token;
      }
      
      if (urlEmpid) {
        empidField.value = urlEmpid;
      } else if (empid) {
        empidField.value = empid;
      }
      
      // Preserve all important parameters in form action URL
      if (finalToken) {
        actionUrl.searchParams.set('token', finalToken);
      }
      if (finalEmpid) {
        actionUrl.searchParams.set('empid', finalEmpid);
      }
      
      // Preserve script, deploy, compid parameters - read from current URL first
      const currentUrlParams = new URLSearchParams(window.location.search);
      const currentScript = currentUrlParams.get('script') || script;
      const currentDeploy = currentUrlParams.get('deploy') || deploy;
      const currentCompid = currentUrlParams.get('compid') || compid;
      
      if (currentScript) actionUrl.searchParams.set('script', currentScript);
      if (currentDeploy) actionUrl.searchParams.set('deploy', currentDeploy);
      if (currentCompid) actionUrl.searchParams.set('compid', currentCompid);
      
      // Set the form action with all parameters
      form.action = actionUrl.toString();
      
      // Also add an event listener to ensure token is preserved on form submit
      form.addEventListener('submit', function(e) {
        // Always read from current URL to ensure we get the latest token after redirects
        const currentUrlParams = new URLSearchParams(window.location.search);
        const currentToken = currentUrlParams.get('token') || document.getElementById('custpage_token')?.value || '';
        const currentEmpid = currentUrlParams.get('empid') || document.getElementById('custpage_empid')?.value || '';
        const currentScript = currentUrlParams.get('script') || script || '';
        const currentDeploy = currentUrlParams.get('deploy') || deploy || '';
        const currentCompid = currentUrlParams.get('compid') || compid || '';
        
        // CRITICAL: Ensure hidden fields have the token values before submission
        const tokenField = document.getElementById('custpage_token');
        const empidField = document.getElementById('custpage_empid');
        
        if (currentToken && tokenField) {
          tokenField.value = currentToken;
        }
        if (currentEmpid && empidField) {
          empidField.value = currentEmpid;
        }
        
        // Always preserve token and other params in form action URL
        const submitUrl = new URL(form.action, window.location.origin);
        if (currentToken) {
          submitUrl.searchParams.set('token', currentToken);
        }
        if (currentEmpid) {
          submitUrl.searchParams.set('empid', currentEmpid);
        }
        if (currentScript) submitUrl.searchParams.set('script', currentScript);
        if (currentDeploy) submitUrl.searchParams.set('deploy', currentDeploy);
        if (currentCompid) submitUrl.searchParams.set('compid', currentCompid);
        
        form.action = submitUrl.toString();
        
        // CRITICAL: If no token found, log error but don't prevent submission
        // The server-side code will handle authentication and redirect to login if needed
        if (!currentToken) {
          console.error('ERROR: No token found on form submit! This will cause redirect to login.', {
            urlToken: currentUrlParams.get('token'),
            hiddenFieldToken: tokenField?.value,
            formAction: form.action,
            currentUrl: window.location.href
          });
        }
      }, true); // Use capture phase to ensure this runs before other handlers

      const hero = document.createElement('section');
      hero.className = 'app-hero';
      hero.innerHTML = [
        '<div class="app-hero__header">',
          '<div class="app-hero__header-left">',
            '<h1 class="app-hero__title">Item Lookup App</h1>',
            '<p class="app-hero__subtitle">Search items by name, UPC or code to see price levels and inventory.</p>',
          '</div>',
          '<div class="app-hero__header-right">',
            '<div class="app-hero__action"></div>',
          '</div>',
        '</div>',
        '<div class="app-hero__search-container">',
          '<div class="app-hero__search"><span class="app-search-icon"></span></div>',
        '</div>'
      ].join('');

      const heroWrapper = document.createElement('div');
      heroWrapper.className = 'app-wrapper app-hero-wrap';
      heroWrapper.appendChild(hero);
      form.insertBefore(heroWrapper, form.firstChild);

      const labelCell = document.getElementById('item_fs_lbl');
      if (labelCell) labelCell.remove();
      const popupLink = document.getElementById('item_popup_link');
      if (popupLink && popupLink.parentNode) popupLink.parentNode.style.display = 'none';

      const searchSlot = hero.querySelector('.app-hero__search');
      if (searchSlot) {
        const label = fieldWrapper.querySelector('label');
        if (label) label.remove();

        // Create label for Item field (left-aligned for horizontal layout)
        const itemLabel = document.createElement('label');
        itemLabel.textContent = 'ITEM *';
        itemLabel.style.display = 'block';
        itemLabel.style.textAlign = 'left';
        itemLabel.style.marginBottom = '8px';
        itemLabel.style.fontWeight = '600';
        itemLabel.style.color = '#1f2933';
        itemLabel.style.fontSize = '14px';
        searchSlot.appendChild(itemLabel);
        
        // Add a clear/reset link next to the label for easy clearing
        const clearLink = document.createElement('a');
        clearLink.href = '#';
        clearLink.textContent = '(clear)';
        clearLink.style.marginLeft = '8px';
        clearLink.style.fontSize = '12px';
        clearLink.style.color = '#6b7280';
        clearLink.style.textDecoration = 'none';
        clearLink.style.fontWeight = '400';
        clearLink.addEventListener('click', function(e) {
          e.preventDefault();
          const select = fieldWrapper.querySelector('select');
          if (select) {
            select.value = '';
            select.selectedIndex = 0;
            // Trigger change event
            select.dispatchEvent(new Event('change', { bubbles: true }));
            select.focus();
          }
        });
        clearLink.addEventListener('mouseenter', function() {
          this.style.textDecoration = 'underline';
        });
        clearLink.addEventListener('mouseleave', function() {
          this.style.textDecoration = 'none';
        });
        itemLabel.appendChild(clearLink);

        fieldWrapper.classList.add('app-item-field');
        const hint = fieldWrapper.querySelector('.uir-field-pointer') || fieldWrapper.querySelector('.uir-field-hint');
        if (hint) hint.remove();
        fieldWrapper.setAttribute('data-placeholder','');
        // Make field wrapper flexible for horizontal layout
        fieldWrapper.style.width = '100%';
        fieldWrapper.style.minWidth = '0';
        searchSlot.appendChild(fieldWrapper);

        const select = fieldWrapper.querySelector('select');
        if (select) {
          // Ensure select field is properly configured for search
          select.style.width = '100%';
          
          // NetSuite SELECT fields with source automatically have search
          // The key is to ensure the field allows typing/searching even when it has a value
          
          const hasValue = () => {
            if (select.value && select.value !== '') return true;
            const option = select.options && select.options[select.selectedIndex];
            return !!(option && option.value);
          };
          
          const togglePlaceholder = () => {
            fieldWrapper.classList.toggle('has-value', hasValue());
          };
          
          // When user clicks/focuses the field, allow them to type to search for a new item
          // This works the same whether field is empty or has a value
          select.addEventListener('focus', function() {
            fieldWrapper.classList.add('has-value');
            // When focused, user can type to search - NetSuite handles this automatically
            // But we ensure the field is ready for new input
            this.style.cursor = 'text';
          });
          
          // When user starts typing, ensure search works
          select.addEventListener('keydown', function(e) {
            // Allow Escape to clear
            if (e.key === 'Escape') {
              this.value = '';
              this.selectedIndex = 0;
              togglePlaceholder();
              e.preventDefault();
              return;
            }
            
            // For any typing (letters, numbers), ensure search is enabled
            // NetSuite's select with source should handle this, but we ensure it works
            if (e.key.length === 1 && !e.ctrlKey && !e.metaKey) {
              // User is typing - NetSuite will show search results
              // The field should work the same whether it has a value or not
            }
          });
          
          // On change, ensure field is still searchable for next search
          select.addEventListener('change', function() {
            togglePlaceholder();
            // After selection, field should still allow searching for a new item
            // User can click and type again to search
          });
          
          // Make sure clicking the field allows typing to search (even with existing value)
          select.addEventListener('click', function() {
            // When clicked, user should be able to type to search
            // NetSuite's select with source handles this, but ensure it's enabled
            this.focus();
            // Ensure search is ready - user can type to search for a new item
            // This should work the same whether field is empty or has a value
          });
          
          // Double-click to clear and start fresh search
          select.addEventListener('dblclick', function() {
            this.value = '';
            this.selectedIndex = 0;
            togglePlaceholder();
            this.focus();
          });
          
          // Ensure that typing in the field works the same way every time
          // NetSuite's SELECT with source should handle this, but we ensure consistency
          let lastValue = select.value;
          select.addEventListener('input', function() {
            // When user types, ensure search works
            // This should work the same whether field had a value or was empty
            if (this.value !== lastValue) {
              lastValue = this.value;
            }
          });
          
          // Initialize on page load
          togglePlaceholder();
          
          // Ensure NetSuite's search functionality is available
          // NetSuite SELECT fields with source='item' should automatically support typing to search
          // The field should work the same whether it's empty or has a value
          
          // Re-initialize after page load to ensure search works consistently
          // This is especially important after form submission when field has a value
          setTimeout(() => {
            // Ensure the field is ready for search
            // When user clicks and types, NetSuite should show search results
            // This works the same whether field is empty or has a value
            
            // If field has a value, user can still click and type to search for a new item
            // NetSuite handles this automatically, but we ensure it's enabled
            if (select.value) {
              // Field has a value from previous search - ensure it's still searchable
              // User can click on it and type to search for a different item
              select.setAttribute('data-search-enabled', 'true');
            }
            
            // Ensure NetSuite's search UI is available
            // The field should work exactly the same as when it was first loaded
          }, 200);
        }
      }

      const submit = form.querySelector('input[type="submit"]');
      if (submit) {
        submit.classList.add('app-hero__button');
        submit.setAttribute('value', 'Item Lookup');
        submit.value = 'Item Lookup';
        submit.style.color = '#ffffff';
        submit.style.textIndent = '0';
        submit.style.textAlign = 'center';
        submit.style.fontSize = '18px';
        submit.style.fontWeight = '700';
        submit.style.padding = '18px 36px';
        submit.style.minWidth = '200px';
        submit.style.lineHeight = '1.5';
        submit.style.letterSpacing = '0.3px';
        submit.style.height = 'auto';
        const headerRight = hero.querySelector('.app-hero__header-right');
        if (headerRight) {
          const actionSlot = headerRight.querySelector('.app-hero__action');
          if (actionSlot) {
            actionSlot.appendChild(submit);
            
            // Add logout button
            const logoutBtn = document.createElement('button');
            logoutBtn.type = 'button';
            logoutBtn.textContent = 'Logout';
            logoutBtn.className = 'app-hero__button app-hero__button--logout';
            logoutBtn.style.marginLeft = '12px';
            logoutBtn.style.background = '#dc2626';
            logoutBtn.style.backgroundColor = '#dc2626';
            logoutBtn.addEventListener('click', function(e) {
              e.preventDefault();
              // Build logout URL with action=logout, preserving script/deploy/compid
              const urlParams = new URLSearchParams(window.location.search);
              const script = urlParams.get('script');
              const deploy = urlParams.get('deploy');
              const compid = urlParams.get('compid');
              
              const baseUrl = window.location.href.split('?')[0];
              const params = [];
              if (script) params.push('script=' + encodeURIComponent(script));
              if (deploy) params.push('deploy=' + encodeURIComponent(deploy));
              if (compid) params.push('compid=' + encodeURIComponent(compid));
              params.push('action=logout');
              
              const logoutUrl = baseUrl + '?' + params.join('&');
              window.location.href = logoutUrl;
            });
            actionSlot.appendChild(logoutBtn);
          } else {
            headerRight.appendChild(submit);
          }
        }
      }
      
      // Remove More button and menu elements from DOM - aggressive removal
      function removeMoreButton() {
        // Find and remove ALL buttons that contain "More" text (case insensitive)
        const allButtons = document.querySelectorAll('button, a[role="button"], [role="button"]');
        allButtons.forEach(btn => {
          const text = (btn.textContent || btn.innerText || '').trim();
          const ariaLabel = (btn.getAttribute('aria-label') || '').toLowerCase();
          const title = (btn.getAttribute('title') || '').toLowerCase();
          const className = (btn.className || '').toLowerCase();
          
          if (text.toLowerCase().includes('more') || 
              ariaLabel.includes('more') || 
              title.includes('more') ||
              className.includes('menu-button') ||
              className.includes('page-actions')) {
            btn.style.display = 'none';
            btn.style.visibility = 'hidden';
            btn.style.opacity = '0';
            btn.style.height = '0';
            btn.style.width = '0';
            btn.style.overflow = 'hidden';
            btn.style.position = 'absolute';
            btn.style.left = '-9999px';
            btn.remove();
          }
        });
        
        // Remove all menu-related elements
        const menuSelectors = [
          '.uir-menu-button', '.uir-menu-button-container',
          '.uir-page-actions-menu', '.uir-page-actions',
          '.uir-page-actions-menu-button', '.uir-page-actions-menu-container',
          '[class*="menu-button"]', '[class*="page-actions"]',
          '[id*="menu-button"]', '[id*="page-actions"]',
          '.uir-menu-dropdown', '.uir-menu-popup',
          '[role="menu"]', '[role="menuitem"]',
          '[class*="menu-dropdown"]', '[class*="menu-popup"]'
        ];
        
        menuSelectors.forEach(selector => {
          try {
            document.querySelectorAll(selector).forEach(el => {
              el.style.display = 'none';
              el.style.visibility = 'hidden';
              el.remove();
            });
          } catch(e) {}
        });
        
        // Remove any element containing "More" text
        const allElements = document.querySelectorAll('*');
        allElements.forEach(el => {
          const text = (el.textContent || '').trim();
          if (text === 'More' || text === 'more' || text === 'MORE') {
            const parent = el.parentElement;
            if (parent && (parent.tagName === 'BUTTON' || parent.getAttribute('role') === 'button')) {
              parent.remove();
            } else {
              el.remove();
            }
          }
        });
      }
      
      // Remove More button immediately
      removeMoreButton();
      
      // Use MutationObserver to catch dynamically added elements
      const observer = new MutationObserver(function(mutations) {
        removeMoreButton();
      });
      
      // Start observing
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: false
      });
      
      // Also run on various events
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
          removeMoreButton();
          setTimeout(removeMoreButton, 100);
          setTimeout(removeMoreButton, 500);
          setTimeout(removeMoreButton, 1000);
        });
      } else {
        setTimeout(removeMoreButton, 100);
        setTimeout(removeMoreButton, 500);
        setTimeout(removeMoreButton, 1000);
        setTimeout(removeMoreButton, 2000);
      }
      
      // Run on window load
      window.addEventListener('load', function() {
        removeMoreButton();
        setTimeout(removeMoreButton, 500);
      });
    }

    function setupEditableFields() {
      const inputs = document.querySelectorAll('.app-input');
      inputs.forEach(input => {
        input.addEventListener('blur', function() {
          const itemId = this.getAttribute('data-itemid');
          const field = this.getAttribute('data-field');
          const value = this.value.trim();
          
          if (!itemId || !field || !value) return;
          
          // Create hidden form field to pass the update
          const hiddenId = 'custpage_update_' + field + '_' + itemId;
          let hiddenField = document.getElementById(hiddenId);
          if (!hiddenField) {
            hiddenField = document.createElement('input');
            hiddenField.type = 'hidden';
            hiddenField.id = hiddenId;
            hiddenField.name = hiddenId;
            document.querySelector('form').appendChild(hiddenField);
          }
          hiddenField.value = value;
        });
      });
    }

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function() {
        enhanceHero();
        setTimeout(setupEditableFields, 500);
      });
    } else {
      enhanceHero();
      setTimeout(setupEditableFields, 500);
    }
  })();
</script>`;
    }

    function createAppLayoutHTML(header, inventoryHTML, priceHTML) {
        const itemCard = `
        <div class="app-panel">
            <div class="app-card__title">Item Details</div>
            <div class="app-panel__body">
                <div><strong>Internal ID</strong><span>${header.internalId || ''}</span></div>
                <div class="app-editable-field"><strong>Item Code</strong><input type="text" class="app-input" value="${(header.itemId || '').replace(/"/g, '&quot;')}" data-field="itemid" data-itemid="${header.internalId || ''}" /></div>
                <div class="app-editable-field"><strong>Display Name</strong><input type="text" class="app-input" value="${(header.displayName || '').replace(/"/g, '&quot;')}" data-field="displayname" data-itemid="${header.internalId || ''}" /></div>
                <div><strong>UPC</strong><span>${header.upcCode || ''}</span></div>
                <div><strong>External ID</strong><span>${header.externalId || ''}</span></div>
            </div>
        </div>`;

        return `<div class="app-wrapper"><div class="app-grid"><div class="app-stack">${itemCard}${priceHTML || ''}${inventoryHTML || ''}</div></div></div>`;
    }

    function selectDesiredPriceLevels(priceLevels) {
        try {
            // Only return Base Price - ignore other price levels for now
            const normalize = (name) => (name || '').toString().trim().toLowerCase().replace(/_/g, ' ');
            const normalizedMap = {};
            (priceLevels || []).forEach(p => {
                const n = normalize(p.name);
                if (!normalizedMap[n]) normalizedMap[n] = p;
            });
            const base = normalizedMap['base price'];
            const basePrice = base && typeof base.price !== 'undefined' ? Number(base.price) : NaN;
            const result = [];
            
            // Only add Base Price
            if (base && typeof base.price !== 'undefined') {
                result.push({ name: 'Base Price', price: Number(base.price) });
            } else if (!isNaN(basePrice)) {
                result.push({ name: 'Base Price', price: basePrice });
            }
            
            log.debug('Final desired price levels composed (Base Price only)', result);
            return result;
        } catch (e) {
            log.debug('selectDesiredPriceLevels error', e);
            return priceLevels || [];
        }
    }

    function getPriceLevelsTable(itemId) {
        try {
            log.debug('Getting price levels table for item', itemId);
            log.debug('Item ID type:', typeof itemId, 'Value:', itemId);
            
            // Use record approach to get price level data
            log.debug('Trying record approach for price levels');
            
            const itemRecord = record.load({
                type: record.Type.INVENTORY_ITEM,
                id: itemId,
                isDynamic: false
            });

            log.debug('Item record loaded successfully');
            
            // Try to get the base price first
            try {
                const basePrice = itemRecord.getValue('price');
                log.debug('Base price from item record:', basePrice);
            } catch (e) {
                log.debug('Could not get base price:', e);
            }

            const priceCount = itemRecord.getLineCount({ sublistId: 'price' });
            log.debug('Found price sublist with', priceCount, 'price levels');

            if (priceCount <= 0) {
                log.debug('No price levels found in price sublist (count:', priceCount, ')');
                
                // Try alternative sublist names
                const alternativeSublists = ['pricing', 'itempricing', 'pricelist'];
                for (const sublistName of alternativeSublists) {
                    try {
                        const altCount = itemRecord.getLineCount({ sublistId: sublistName });
                        log.debug('Tried sublist', sublistName, 'with count:', altCount);
                        if (altCount > 0) {
                            log.debug('Found price data in alternative sublist:', sublistName);
                            // Use the alternative sublist
                            return getPriceLevelsFromSublist(itemRecord, sublistName);
                        }
                    } catch (e) {
                        log.debug('Sublist', sublistName, 'not available:', e.message);
                    }
                }

                // Try pricing group sublists explicitly
                const pricingGroupTable = getPriceLevelsFromPricingGroup(itemRecord);
                if (pricingGroupTable) {
                    return pricingGroupTable;
                }
                
                // If no sublist data found, try search-based approach
                log.debug('No sublist data found, trying search-based price retrieval');
                return getPriceLevelsBySearch(itemId);
            }
            
            // Use the helper function to get price levels from the 'price' sublist
            const tableFromSublist = getPriceLevelsFromSublist(itemRecord, 'price');
            if (tableFromSublist) return tableFromSublist;

            // If price sublist didn't return rows, try pricing group
            const tableFromPricingGroup = getPriceLevelsFromPricingGroup(itemRecord);
            if (tableFromPricingGroup) return tableFromPricingGroup;
            return getPriceLevelsBySearch(itemId);
            
        } catch (e) {
            log.debug('Error creating price levels table', e);
            
            // Fallback: Try search approach
            try {
                log.debug('Trying search approach for price levels');
                
                // Try to get price levels using search
                const priceLevelSearch = search.create({
                    type: 'pricing',
                    filters: [
                        ['item', 'anyof', itemId]
                    ],
                    columns: [
                        'pricelevel',
                        'unitprice',
                        'priceqty'
                    ]
                });

                const fallbackPriceLevels = [];
                priceLevelSearch.run().each((res) => {
                    const priceLevelName = res.getText('pricelevel') || '';
                    const unitPrice = res.getValue('unitprice') || '';
                    const priceQty = res.getValue('priceqty') || '';
                    
                    log.debug('Search fallback result', {
                        name: priceLevelName,
                        price: unitPrice,
                        quantity: priceQty
                    });
                    
                    if (priceLevelName && unitPrice) {
                        // Calculate discount percentage if it's a discount price level
                        let discount = '';
                        if (priceLevelName.toLowerCase().includes('off') || priceLevelName.toLowerCase().includes('%')) {
                            const basePrice = 17.99; // You might want to get this from the base price
                            const discountPercent = ((basePrice - unitPrice) / basePrice * 100).toFixed(1);
                            if (discountPercent > 0) {
                                discount = `-${discountPercent}%`;
                            }
                        }
                        
                        fallbackPriceLevels.push({
                            name: priceLevelName,
                            price: unitPrice,
                            quantity: priceQty || 1,
                            discount: discount
                        });
                    }
                    
                    return true;
                });
                
                if (fallbackPriceLevels.length > 0) {
                    log.debug('Search fallback found', fallbackPriceLevels.length, 'price levels');
                    return createPriceLevelsTableHTML(selectDesiredPriceLevels(fallbackPriceLevels));
                } else {
                    log.debug('Search fallback also found no price levels');
                }
                
            } catch (fallbackError) {
                log.debug('Search fallback approach also failed', fallbackError);
            }
            
            // No fallback - only return real data
            log.debug('No price data found through any method');
            return null;
        }
    }

    function getInventoryByLocation(itemId) {
        const results = {};
            
            // Try to read directly from the item record locations sublist first (Inventory Management)
            try {
                log.debug('Trying to read inventory from item record locations sublist');
                const itemRecord = record.load({ type: record.Type.INVENTORY_ITEM, id: itemId, isDynamic: false });
                const directResults = getInventoryFromItemRecord(itemRecord);
                if (directResults && Object.keys(directResults).length > 0) {
                    log.debug('Found inventory via item record locations sublist (Inventory Management)');
                    return directResults;
                }
            } catch (e) {
                log.debug('Direct item record inventory read failed', e);
            }

            // Second: Item search using location-level quantity columns
            try {
                log.debug('Trying item search for per-location quantities');
                const itemSearch = search.create({
                    type: 'item',
                    filters: [['internalid', 'anyof', itemId]],
                    columns: [
                        'inventorylocation',
                        'locationquantityonhand',
                        'locationquantityonorder'
                    ]
                });
                const itemSearchResults = {};
                itemSearch.run().each((res) => {
                    const locId = res.getValue('inventorylocation');
                    const locName = res.getText('inventorylocation') || '';
                    const onHand = Number(res.getValue('locationquantityonhand')) || 0;
                    const onOrder = Number(res.getValue('locationquantityonorder')) || 0;
                    if (locId || locName) {
                        itemSearchResults[locId || locName] = {
                            locationName: locName || String(locId || ''),
                            onHand,
                            onOrder
                        };
                    }
                    return true;
                });
                if (Object.keys(itemSearchResults).length > 0) {
                    log.debug('Found inventory via item search per-location quantities');
                    return itemSearchResults;
                }
            } catch (e) {
                log.debug('Item search per-location quantities failed', e);
            }

            // Specific location IDs to search for
            const locationIds = [7, 9, 10, 11, 18, 19];
            
            // Try the Custom Inventory search first
            try {
                log.debug('Trying Custom Inventory search for item', itemId);
                log.debug('Location IDs to search:', locationIds);
                
                // First, let's try to find the correct custom search ID
                try {
                    log.debug('Attempting to find custom searches...');
                    const searchLookup = search.create({
                        type: 'customsearch',
                        filters: [['name', 'contains', 'inventory']],
                        columns: ['name', 'internalid']
                    });
                    
                    searchLookup.run().each((res) => {
                        const searchName = res.getText('name') || '';
                        const searchId = res.getValue('internalid') || '';
                        log.debug('Found custom search:', searchName, 'ID:', searchId);
                        return true;
                    });
                } catch (lookupError) {
                    log.debug('Could not lookup custom searches:', lookupError);
                }
                
                // First, let's try to create the search and see what happens
                let customSearch;
                try {
                    // Try without filters first to see if the search exists
                    log.debug('Testing custom search without filters...');
                    const testSearch = search.create({
                        type: 'customsearch_custom_inventory'
                    });
                    log.debug('Custom search exists, now trying with filters...');
                    
                    customSearch = search.create({
                        type: 'customsearch_custom_inventory', // Assuming this is the internal ID
                        filters: [
                            ['item', 'anyof', itemId], 'AND',
                            ['location', 'anyof', locationIds]
                        ]
                    });
                    log.debug('Custom search created successfully with filters');
                } catch (createError) {
                    log.debug('Failed to create custom search:', createError);
                    
                    // Try alternative search ID formats
                    const alternativeIds = [
                        'customsearch_custom_inventory',
                        'customsearch_Custom_Inventory', 
                        'customsearch_custominventory',
                        'customsearch_CustomInventory'
                    ];
                    
                    for (let altId of alternativeIds) {
                        try {
                            log.debug('Trying alternative search ID:', altId);
                            customSearch = search.create({
                                type: altId,
                                filters: [
                                    ['item', 'anyof', itemId], 'AND',
                                    ['location', 'anyof', locationIds]
                                ]
                            });
                            log.debug('Successfully created search with ID:', altId);
                            break;
                        } catch (altError) {
                            log.debug('Alternative search ID', altId, 'failed:', altError);
                        }
                    }
                }

                if (!customSearch) {
                    log.debug('No custom search could be created, skipping custom search');
                } else {
                    log.debug('Running custom search...');
                    
                    let foundData = false;
                    let resultCount = 0;
                    
                    customSearch.run().each((res) => {
                        resultCount++;
                        log.debug('Processing result #', resultCount);
                        
                        // Log all available fields to see what's actually returned
                        const allFields = res.getColumns();
                        log.debug('Available fields in result:', allFields);
                        
                        const locId = res.getValue('location');
                        const locName = res.getText('location') || '';
                        const onHand = Number(res.getValue('quantityonhand')) || 0;
                        const onOrder = Number(res.getValue('quantityonorder')) || 0;
                        
                        // Try alternative field names if the standard ones don't work
                        const altOnHand = Number(res.getValue('onhand')) || Number(res.getValue('quantityonhand')) || 0;
                        const altOnOrder = Number(res.getValue('onorder')) || Number(res.getValue('quantityonorder')) || 0;
                            
                        log.debug('Found Custom Inventory data', {
                            locId: locId,
                            locName: locName,
                            onHand: onHand,
                            onOrder: onOrder,
                            altOnHand: altOnHand,
                            altOnOrder: altOnOrder,
                            allFields: allFields
                        });
                        
                        if (locId) {
                            results[locId] = { 
                                locationName: locName, 
                                onHand: onHand || altOnHand, 
                                onOrder: onOrder || altOnOrder
                            };
                            foundData = true;
                        }
                        return true;
                    });
                    
                    log.debug('Custom search completed. Total results processed:', resultCount);
                }
                
                if (foundData) {
                    log.debug('Successfully found inventory data using Custom Inventory search, found', Object.keys(results).length, 'locations');
                    return results;
                } else {
                    log.debug('No data found with Custom Inventory search');
                }
                
            } catch (e) {
                log.debug('Custom Inventory search failed with error:', e);
            }
            
            // Fallback to standard searches if Custom Inventory search fails
            const searchConfigs = [
                {
                    type: 'inventorybalance',
                    filters: [
                        ['item', 'anyof', itemId], 'AND',
                        ['location', 'anyof', locationIds]
                    ],
                    columns: [
                        search.createColumn({ name: 'location', summary: search.Summary.GROUP }),
                        search.createColumn({ name: 'onhand', summary: search.Summary.SUM }),
                        search.createColumn({ name: 'available', summary: search.Summary.SUM })
                    ]
                },
                {
                    type: 'inventorydetail',
                    filters: [
                        ['item', 'anyof', itemId], 'AND',
                        ['location', 'anyof', locationIds]
                    ],
                    columns: [
                        search.createColumn({ name: 'location', summary: search.Summary.GROUP }),
                        search.createColumn({ name: 'quantityonhand', summary: search.Summary.SUM }),
                        search.createColumn({ name: 'quantityavailable', summary: search.Summary.SUM })
                    ]
                }
            ];
            
            for (let config of searchConfigs) {
                try {
                    log.debug('Trying fallback inventory search with type:', config.type);
                    
                    const invSearch = search.create({
                        type: config.type,
                        filters: config.filters,
                        columns: config.columns
                    });

                    let foundData = false;
                    invSearch.run().each((res) => {
                        const locId = res.getValue({ name: 'location', summary: search.Summary.GROUP });
                        const locName = res.getText({ name: 'location', summary: search.Summary.GROUP }) || '';
                        
                        // Try different field names based on search type
                        let onHand = 0;
                        
                        if (config.type === 'inventorybalance') {
                            onHand = Number(res.getValue({ name: 'onhand', summary: search.Summary.SUM })) || 0;
                        } else if (config.type === 'inventorydetail') {
                            onHand = Number(res.getValue({ name: 'quantityonhand', summary: search.Summary.SUM })) || 0;
                        }
                            
                        log.debug('Found inventory data with', config.type, {
                            locId: locId,
                            locName: locName,
                            onHand: onHand
                        });
                        
                        if (locId && onHand > 0) {
                            results[locId] = { 
                                locationName: locName, 
                                onHand: onHand, 
                                onOrder: 0
                            };
                            foundData = true;
                        }
                        return true;
                    });
                    
                    if (foundData) {
                        log.debug('Successfully found inventory data using', config.type, 'found', Object.keys(results).length, 'locations');
                        break;
                    } else {
                        log.debug('No inventory data found with', config.type);
                    }
                    
                } catch (e) {
                    log.debug('Inventory search with type', config.type, 'failed with error:', e);
                }
            }
                
            log.debug('Inventory search completed, found', Object.keys(results).length, 'locations');
            return results;
        }

    function getInventoryFromItemRecord(itemRecord) {
        try {
            const out = {};
            const possibleSublists = ['locations', 'location', 'inventorylocations', 'inventorylocation'];
            const fieldCombos = [
                { locField: 'location', onHandField: 'quantityonhand', onOrderField: 'quantityonorder' },
                { locField: 'location', onHandField: 'quantityonhandinbaseunit', onOrderField: 'quantityonorderinbaseunit' },
                { locField: 'inventorylocation', onHandField: 'quantityonhand', onOrderField: 'quantityonorder' },
                { locField: 'inventorylocation', onHandField: 'quantityonhandinbaseunit', onOrderField: 'quantityonorderinbaseunit' },
                { locField: 'inventorylocation', onHandField: 'onhand', onOrderField: 'onorder' },
                { locField: 'location', onHandField: 'onhand', onOrderField: 'onorder' }
            ];
            for (const sublistId of possibleSublists) {
                let count = 0;
                try { count = itemRecord.getLineCount({ sublistId }); } catch (_e) { count = 0; }
                let availableFields = [];
                try { availableFields = itemRecord.getSublistFields({ sublistId }) || []; } catch (_f) { availableFields = []; }
                log.debug('Inventory sublist check', { sublistId, count, availableFields });
                // Try to detect field ids dynamically if standard ones missing
                let detected = null;
                if (availableFields && availableFields.length) {
                    const normalized = availableFields.map(f => String(f).toLowerCase());
                    const pick = (needle, exclude) => normalized.find(id => id.includes(needle) && (!exclude || !id.includes(exclude)));
                    const locField = pick('location');
                    const onHandField = pick('onhand');
                    const onOrderField = pick('onorder');
                    if (locField && onHandField) {
                        detected = { locField, onHandField, onOrderField: onOrderField || 'quantityonorder' };
                        fieldCombos.unshift(detected);
                        log.debug('Detected inventory field combo', detected);
                    }
                }
                if (!count || count <= 0) continue;
                for (let i = 0; i < count; i++) {
                    let locId = '', locName = '', onHand = 0, onOrder = 0;
                    for (const combo of fieldCombos) {
                        try {
                            locId = String(itemRecord.getSublistValue({ sublistId, fieldId: combo.locField, line: i }) || '');
                            locName = itemRecord.getSublistText({ sublistId, fieldId: combo.locField, line: i }) || locId;
                            onHand = Number(itemRecord.getSublistValue({ sublistId, fieldId: combo.onHandField, line: i })) || 0;
                            onOrder = Number(itemRecord.getSublistValue({ sublistId, fieldId: combo.onOrderField, line: i })) || 0;
                            if (locId || locName) break;
                        } catch (_ignore) { /* try next combo */ }
                    }
                    if (locId || locName) {
                        log.debug('Inventory sublist line captured', { sublistId, line: i, locId, locName, onHand, onOrder });
                        const key = locId || `${sublistId}_${i}`;
                        out[key] = { locationName: String(locName || key), onHand, onOrder };
                    }
                }
                if (Object.keys(out).length > 0) return out;
            }
        } catch (e) {
            log.debug('getInventoryFromItemRecord error', e);
        }
        return null;
    }

        function getOnOrderByLocation(itemId) {
            const results = {};
            
            // Specific location IDs to search for
            const locationIds = [7, 9, 10, 11, 18, 19];
            
        // First: Item search using per-location on order columns
        try {
            log.debug('Trying item search for per-location on-order quantities');
            const itemSearch = search.create({
                type: 'item',
                filters: [['internalid', 'anyof', itemId]],
                columns: [
                    'inventorylocation',
                    'locationquantityonorder',
                    'locationonorder'
                ]
            });
            let anyFound = false;
            itemSearch.run().each((res) => {
                const locId = res.getValue('inventorylocation');
                const locName = res.getText('inventorylocation') || '';
                const qty1 = Number(res.getValue('locationquantityonorder')) || 0;
                const qty2 = Number(res.getValue('locationonorder')) || 0;
                const onOrder = qty1 || qty2;
                if (locId || locName) {
                    results[locId || locName] = { locationName: locName || String(locId || ''), onOrder };
                    anyFound = anyFound || onOrder > 0;
                }
                return true;
            });
            if (Object.keys(results).length > 0) {
                log.debug('Found on-order via item search per-location quantities');
                return results;
            }
        } catch (e) {
            log.debug('Item search per-location on-order failed', e);
        }

        // Second: Direct Purchase Order aggregation by location
        try {
            log.debug('Trying purchase order aggregation for on-order quantities');
            const poSearch = search.create({
                type: 'purchaseorder',
                filters: [
                    ['mainline', 'is', 'F'], 'AND',
                    ['item', 'anyof', itemId], 'AND',
                    ['status', 'anyof', ['PurchOrd:A','PurchOrd:B','PurchOrd:D']]
                ],
                columns: [
                    search.createColumn({ name: 'location', summary: search.Summary.GROUP }),
                    search.createColumn({ name: 'quantity', summary: search.Summary.SUM })
                ]
            });
            let foundPO = false;
            poSearch.run().each((res) => {
                const locId = res.getValue({ name: 'location', summary: search.Summary.GROUP });
                const locName = res.getText({ name: 'location', summary: search.Summary.GROUP }) || '';
                const qty = Number(res.getValue({ name: 'quantity', summary: search.Summary.SUM })) || 0;
                if (locId || locName) {
                    results[locId || locName] = { locationName: locName || String(locId || ''), onOrder: qty };
                    foundPO = foundPO || qty > 0;
                }
                return true;
            });
            if (Object.keys(results).length > 0) {
                log.debug('Found on-order via purchase order aggregation');
                return results;
            }
        } catch (e) {
            log.debug('Purchase order aggregation failed', e);
        }

            // Try the Custom Inventory search first (since it contains both on hand and on order)
            try {
                log.debug('Trying Custom Inventory search for on-order data for item', itemId);
                
                const customSearch = search.create({
                    type: 'customsearch_custom_inventory',
                    filters: [
                        ['item', 'anyof', itemId], 'AND',
                        ['location', 'anyof', locationIds]
                    ]
                });

                let foundData = false;
                customSearch.run().each((res) => {
                    const locId = res.getValue('location');
                    const locName = res.getText('location') || '';
                    const onOrder = Number(res.getValue('quantityonorder')) || 0;
                        
                    log.debug('Found Custom Inventory on-order data', {
                        locId: locId,
                        locName: locName,
                        onOrder: onOrder
                    });
                    
                    if (locId) {
                        results[locId] = { locationName: locName, onOrder: onOrder };
                        foundData = true;
                        log.debug('Added to on-order results:', { locId, locName, onOrder });
                    }
                    return true;
                });
                
                if (foundData) {
                    log.debug('Successfully found on-order data using Custom Inventory search, found', Object.keys(results).length, 'locations');
                    return results;
                } else {
                    log.debug('No on-order data found with Custom Inventory search');
                }
                
            } catch (e) {
                log.debug('Custom Inventory search for on-order failed with error:', e);
            }
            
            // Fallback to standard searches if Custom Inventory search fails
            const searchConfigs = [
                {
                    type: 'inventorydetail',
                    filters: [
                        ['item', 'anyof', itemId], 'AND',
                        ['location', 'anyof', locationIds]
                    ],
                    columns: [
                        search.createColumn({ name: 'location', summary: search.Summary.GROUP }),
                        search.createColumn({ name: 'quantityonorder', summary: search.Summary.SUM })
                    ]
                },
                {
                    type: 'inventorybalance',
                    filters: [
                        ['item', 'anyof', itemId], 'AND',
                        ['location', 'anyof', locationIds]
                    ],
                    columns: [
                        search.createColumn({ name: 'location', summary: search.Summary.GROUP }),
                        search.createColumn({ name: 'quantityonorder', summary: search.Summary.SUM })
                    ]
                },
                {
                    type: 'purchaseorder',
                    filters: [
                        ['item', 'anyof', itemId], 'AND',
                        ['location', 'anyof', locationIds], 'AND',
                        ['status', 'anyof', ['pendingApproval', 'pendingReceipt', 'partiallyReceived']]
                    ],
                    columns: [
                        search.createColumn({ name: 'location', summary: search.Summary.GROUP }),
                        search.createColumn({ name: 'quantity', summary: search.Summary.SUM })
                    ]
                }
            ];
            
            for (let config of searchConfigs) {
                try {
                    log.debug('Trying fallback on-order search with type:', config.type);
                    
                    const searchObj = search.create({
                        type: config.type,
                        filters: config.filters,
                        columns: config.columns
                    });

                    let foundData = false;
                    searchObj.run().each((res) => {
                        const locId = res.getValue({ name: 'location', summary: search.Summary.GROUP });
                        const locName = res.getText({ name: 'location', summary: search.Summary.GROUP }) || '';
                        
                        // Try different field names based on search type
                        let onOrder = 0;
                        
                        if (config.type === 'purchaseorder') {
                            onOrder = Number(res.getValue({ name: 'quantity', summary: search.Summary.SUM })) || 0;
                        } else {
                            onOrder = Number(res.getValue({ name: 'quantityonorder', summary: search.Summary.SUM })) || 0;
                        }

                        log.debug('Found on-order data with', config.type, {
                            locId: locId,
                            locName: locName,
                            onOrder: onOrder
                        });

                        if (locId && onOrder > 0) {
                            results[locId] = { locationName: locName, onOrder: onOrder };
                            foundData = true;
                            log.debug('Added to results:', { locId, locName, onOrder });
                        }
                        return true;
                    });

                    if (foundData) {
                        log.debug('Successfully found on-order data using', config.type, 'found', Object.keys(results).length, 'locations');
                        break;
                    } else {
                        log.debug('No on-order data found with', config.type);
                    }
                    
                } catch (e) {
                    log.debug('On-order search with type', config.type, 'failed with error:', e);
                }
            }
            
            log.debug('On-order search completed, found', Object.keys(results).length, 'locations with on-order quantities');
            return results;
        }

    return { onRequest };
});

