/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
 */

#import "TouchID.h"
#include <sys/types.h>
#include <sys/sysctl.h>
#import <Cordova/CDV.h>

@implementation TouchID

- (void)isAvailable:(CDVInvokedUrlCommand*)command{
    self.laContext = [[LAContext alloc] init];
    BOOL touchIDAvailable = [self.laContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil];
    if(touchIDAvailable){
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
    else{
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Touch ID not availalbe"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

- (void)setLocale:(CDVInvokedUrlCommand*)command{
  CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
  [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)has:(CDVInvokedUrlCommand*)command{
  	self.TAG = (NSString*)[command.arguments objectAtIndex:0];
    BOOL hasLoginKey = [[NSUserDefaults standardUserDefaults] boolForKey:self.TAG];
    if(hasLoginKey){
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
    else{
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"No Password in chain"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

- (void)save:(CDVInvokedUrlCommand*)command{
	 	self.TAG = (NSString*)[command.arguments objectAtIndex:0];
    NSString* password = (NSString*)[command.arguments objectAtIndex:1];
    @try {
        self.MyKeychainWrapper = [[KeychainWrapper alloc]init];
        [self.MyKeychainWrapper mySetObject:password forKey:(__bridge id)(kSecValueData)];
        [self.MyKeychainWrapper writeToKeychain];
        [[NSUserDefaults standardUserDefaults]setBool:true forKey:self.TAG];
        [[NSUserDefaults standardUserDefaults]synchronize];

        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
    @catch(NSException *exception){
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Password could not be save in chain"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

-(void)delete:(CDVInvokedUrlCommand*)command{
	 	self.TAG = (NSString*)[command.arguments objectAtIndex:0];
    @try {
        [[NSUserDefaults standardUserDefaults] removeObjectForKey:self.TAG];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
    @catch(NSException *exception) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Could not delete password from chain"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }


}

-(void)verify:(CDVInvokedUrlCommand*)command{
	 	self.TAG = (NSString*)[command.arguments objectAtIndex:0];
	  NSString* message = (NSString*)[command.arguments objectAtIndex:1];
    self.laContext = [[LAContext alloc] init];
    self.MyKeychainWrapper = [[KeychainWrapper alloc]init];

    BOOL hasLoginKey = [[NSUserDefaults standardUserDefaults] boolForKey:self.TAG];
    if(hasLoginKey){
        BOOL touchIDAvailable = [self.laContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil];

        if(touchIDAvailable){
            [self.laContext evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:message reply:^(BOOL success, NSError *error) {
                dispatch_async(dispatch_get_main_queue(), ^{

                if(success){
                    NSString *password = [self.MyKeychainWrapper myObjectForKey:@"v_Data"];
									  CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString: password];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
                if(error != nil) {
										CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: [NSString stringWithFormat:@"%li", error.code]];
										[self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
                });
            }];

        }
        else{
            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"-1"];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        }
    }
    else{
           CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"-1"];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}
@end
