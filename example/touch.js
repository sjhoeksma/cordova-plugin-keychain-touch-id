/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
//Use after a cordova create (new project)
//Edit the index.html and add a script tag for this touch.js file under the existing index.js file
//copy this file into the js directory
//Excercises the general API for this plugin
var app = {
    // Application Constructor
    initialize: function() {
        document.addEventListener('deviceready', this.onDeviceReady.bind(this), false);
    },

    // deviceready Event Handler
    //
    // Bind any cordova events here. Common events are:
    // 'pause', 'resume', etc.
    onDeviceReady: function() {
        if (window.plugins) {
	    //save
            window.plugins.touchid.save("MyKey", "My Password", function() {
                alert("Password saved");

                //biometricsType
                window.plugins.touchid.biometricType(function(value) { alert("Biometrics: " + value); }, 
                function() { alert("Biometric error");} );

	        //isAvailable
    	        window.plugins.touchid.isAvailable(function() {

                    //has
                    window.plugins.touchid.has("MyKey", function() {
                        alert("Touch ID avaialble and Password key available");

	               //verify
                       window.plugins.touchid.verify("MyKey", "My Message", function(password) {
                           alert("Touch " + password);

	                   //delete	
                           window.plugins.touchid.delete("MyKey", function() {
                               alert("Password key deleted");
                           });
                       });
                    }, function() {
                        alert("Touch ID available but no Password Key available");
                    });
                }, function(msg) {
                    alert("no Touch ID available");
                });
            });
        }
    }
};

app.initialize();
