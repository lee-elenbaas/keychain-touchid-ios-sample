/*
    Copyright (C) 2015 Apple Inc. All Rights Reserved.
    See LICENSE.txt for this sample’s licensing information
    
    Abstract:
    Keychain with Touch ID demo implementation.
*/

#import "AAPLKeychainTestsViewController.h"
#import "AAPLTest.h"

@import Security;
@import LocalAuthentication;

@implementation AAPLKeychainTestsViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    // prepare the actions which can be tested in this class
    self.tests = @[
                   [[AAPLTest alloc] initWithName:@"lee - check for passcode" details:@"Set item with passcode then remove it" selector:@selector(checkForPasscode)],
                   [[AAPLTest alloc] initWithName:@"lee - validation flow" details:@"Set item with touchID or passcode then attempt to access it" selector:@selector(userPresenseValidation)],
                   [[AAPLTest alloc] initWithName:@"lee - set item" details:@"Set item with touchID or passcode" selector:@selector(addItemLeeAsync)],
                   [[AAPLTest alloc] initWithName:@"lee - set item iOS7" details:@"Set item always accessible" selector:@selector(addItemLeeiOS7Async)],
                   [[AAPLTest alloc] initWithName:@"lee - get item" details:@"Get item with touchID or passcode" selector:@selector(copyMatchingLeeAsync)],
                   [[AAPLTest alloc] initWithName:@"lee - delete item" details:@"No authentication" selector:@selector(deleteItemLeeAsync)],
        [[AAPLTest alloc] initWithName:@"Add item" details:@"Using SecItemAdd()" selector:@selector(addItemAsync)],
        [[AAPLTest alloc] initWithName:@"Add item (TouchID only)" details:@"Using SecItemAdd()" selector:@selector(addTouchIDItemAsync)],
        [[AAPLTest alloc] initWithName:@"Add item (TouchID and password)" details:@"Using SecItemAdd()" selector:@selector(addPwdItem)],
        [[AAPLTest alloc] initWithName:@"Query for item" details:@"Using SecItemCopyMatching()" selector:@selector(copyMatchingAsync)],
        [[AAPLTest alloc] initWithName:@"Update item" details:@"Using SecItemUpdate()" selector:@selector(updateItemAsync)],
        [[AAPLTest alloc] initWithName:@"Delete item" details:@"Using SecItemDelete()" selector:@selector(deleteItemAsync)],
        [[AAPLTest alloc] initWithName:@"Add protected key" details:@"Using SecKeyGeneratePair ()" selector:@selector(generateKeyAsync)],
        [[AAPLTest alloc] initWithName:@"Use protected key" details:@"Using SecKeyRawSign()" selector:@selector(useKeyAsync)],
        [[AAPLTest alloc] initWithName:@"Delete protected key" details:@"Using SecItemDelete()" selector:@selector(deleteKeyAsync)]
    ];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self.textView scrollRangeToVisible:NSMakeRange(self.textView.text.length, 0)];
}

- (void)viewDidLayoutSubviews {
    // Set the proper size for the table view based on its content.
    CGFloat height = MIN(self.view.bounds.size.height, self.tableView.contentSize.height);
    self.dynamicViewHeight.constant = height;

    [self.view layoutIfNeeded];
}

#pragma mark - Tests

- (void)checkForPasscode {
    CFErrorRef error = NULL;

    if (floor(NSFoundationVersionNumber) <= NSFoundationVersionNumber_iOS_7_1)
    {
        NSString *errorString = @"iOS < 8 no touchID and no way to check passcode presence";
        
        [self printMessage:errorString inTextView:self.textView];
        return;
    }
    
    // Should be the secret invalidated when passcode is removed? If not then use kSecAttrAccessibleWhenUnlocked
    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(
                                                                    kCFAllocatorDefault,
                                                                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                                    kSecAccessControlUserPresence, // doesn't really matter
                                                                    &error
                                                                    );
    
    if (sacObject == NULL || error != NULL) {
        NSString *errorString = [NSString stringWithFormat:@"SecItemAdd can't create sacObject: %@", error];
        
        self.textView.text = [self.textView.text stringByAppendingString:errorString];
        
        return;
    }
    NSString *serviceName = @"SampleService";
    NSString *testAttribute = @"PasscodeTest";
    
    // we want the operation to fail if there is an item which needs authentication so we will use
    // kSecUseNoAuthenticationUI
    NSDictionary *attributes = @{
                                 (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                 (__bridge id)kSecAttrService: serviceName, // service name
                                 (__bridge id)kSecAttrAccount: testAttribute, // value name
                                 (__bridge id)kSecValueData: [@"SECRET_PASSWORD_TEXT" dataUsingEncoding:NSUTF8StringEncoding], // value does not matter
                                 (__bridge id)kSecUseOperationPrompt: @"Authenticate to access lee's service password",
                                 (__bridge id)kSecUseNoAuthenticationUI: @YES,
                                 (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject
                                 };
    
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        OSStatus status =  SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
        
        NSString *errorString = [self keychainErrorToString:status];
        NSString *message = [NSString stringWithFormat:@"SecItemAdd status: %@", errorString];
        
        if (errSecSuccess == status) {
            NSDictionary *deleteQuery = @{
                                    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                    (__bridge id)kSecAttrService: serviceName, // service name
                                    (__bridge id)kSecAttrAccount: testAttribute // value name
                                    };
            
            status = SecItemDelete((__bridge CFDictionaryRef)deleteQuery);
            
            errorString = [self keychainErrorToString:status];
            message = [NSString stringWithFormat:@"SecItemDelete status: %@", errorString];
            
        }
        else if (errSecAuthFailed == status) {
            message = @"passcode not set on device";
        }
        
        [self printMessage:message inTextView:self.textView];
    });


}

// from https://www.secsign.com/fingerprint-validation-as-an-alternative-to-passcodes/
- (void)userPresenseValidation {
    // The identifier and service name together will uniquely identify the keychain entry.
    NSString * keychainItemIdentifier = @"fingerprintKeychainEntry";
    NSString * keychainItemServiceName = @"com.secsign.secsign";
    // The content of the password is not important.
    NSData * pwData = [@"the password itself does not matter" dataUsingEncoding:NSUTF8StringEncoding];
    
    // Set the value ----
    
    // Create the keychain entry attributes.
    NSMutableDictionary	* attributes = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                        (__bridge id)(kSecClassGenericPassword), kSecClass,
                                        keychainItemIdentifier, kSecAttrAccount,
                                        keychainItemServiceName, kSecAttrService, nil];
    // Require a fingerprint scan or passcode validation when the keychain entry is read.
    // Apple also offers an option to destroy the keychain entry if the user ever removes the
    // passcode from his iPhone, but we don't need that option here.
    CFErrorRef accessControlError = NULL;
    SecAccessControlRef accessControlRef = SecAccessControlCreateWithFlags(
                                                                           kCFAllocatorDefault,
                                                                           kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                                           kSecAccessControlUserPresence,
                                                                           &accessControlError);
    if (accessControlRef == NULL || accessControlError != NULL)
    {
        NSLog(@"Cannot create SecAccessControlRef to store a password with identifier “%@” in the key chain: %@.", keychainItemIdentifier, accessControlError);
        return;
    }
    attributes[(__bridge id)kSecAttrAccessControl] = (__bridge id)accessControlRef;
    // In case this code is executed again and the keychain item already exists we want an error code instead of a fingerprint scan.
    attributes[(__bridge id)kSecUseNoAuthenticationUI] = @YES;
    attributes[(__bridge id)kSecValueData] = pwData;
    CFTypeRef result;
    OSStatus osStatus = SecItemAdd((__bridge CFDictionaryRef)attributes, &result);
    if (osStatus != noErr)
    {
        NSError * error = [[NSError alloc] initWithDomain:NSOSStatusErrorDomain code:osStatus userInfo:nil];
        NSLog(@"Adding generic password with identifier “%@” to keychain failed with OSError %d: %@.", keychainItemIdentifier, (int)osStatus, error);
    }
    
    /////// accessing the stored value
    
    // Determine a string which the device will display in the fingerprint view explaining the reason for the fingerprint scan.
    NSString * secUseOperationPrompt = @"Authenticate for server login";
    // The keychain operation shall be performed by the global queue. Otherwise it might just nothing happen.
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(void) {
        // Create the keychain query attributes using the values from the first part of the code.
        NSMutableDictionary * query = [[NSMutableDictionary alloc] initWithObjectsAndKeys:
                                       (__bridge id)(kSecClassGenericPassword), kSecClass,
                                       keychainItemIdentifier, kSecAttrAccount,
                                       keychainItemServiceName, kSecAttrService,
                                       secUseOperationPrompt, kSecUseOperationPrompt,
                                       nil];
        // Start the query and the fingerprint scan and/or device passcode validation
        CFTypeRef result = nil;
        OSStatus userPresenceStatus = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        // Ignore the found content of the key chain entry (the dummy password) and only evaluate the return code.
        if (noErr == userPresenceStatus)
        {
            NSLog(@"Fingerprint or device passcode validated.");
        }
        else
        {
            NSLog(@"Fingerprint or device passcode could not be validated. Status %d.", (int) userPresenceStatus);
        }
        // To process the result at this point there would be a call to delegate method which
        // would do its work like GUI operations in the main queue. That means it would start
        // with something like:
        //   dispatch_async(dispatch_get_main_queue(), ^{
    });
}

- (void)addItemLeeiOS7Async {
    CFErrorRef error = NULL;
    
    SecAccessControlRef sacObject = NULL;
    if (floor(NSFoundationVersionNumber) > NSFoundationVersionNumber_iOS_7_1)
    {
        // Should be the secret invalidated when passcode is removed? If not then use kSecAttrAccessibleWhenUnlocked
        sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                    kSecAttrAccessibleAlways, // iOS4+
                                                    kSecAccessControlUserPresence, &error);

        if (sacObject == NULL || error != NULL) {
            NSString *errorString = [NSString stringWithFormat:@"SecItemAdd can't create sacObject: %@", error];
            
            self.textView.text = [self.textView.text stringByAppendingString:errorString];
            
            return;
        }
        
    }
    
    // we want the operation to fail if there is an item which needs authentication so we will use
    // kSecUseNoAuthenticationUI
    NSMutableDictionary *attributes = [@{
                                 (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                 (__bridge id)kSecAttrService: @"SampleService", // service name
                                 (__bridge id)kSecAttrAccount: @"SampleValue", // value name
                                 (__bridge id)kSecValueData: [@"SECRET_PASSWORD_TEXT" dataUsingEncoding:NSUTF8StringEncoding], // value
                                 } mutableCopy];

    if (floor(NSFoundationVersionNumber) > NSFoundationVersionNumber_iOS_7_1)
    {
        //[attributes setObject:@YES forKey:(__bridge id)kSecUseNoAuthenticationUI];
        [attributes setObject:(__bridge_transfer id)sacObject forKey:(__bridge id)kSecAttrAccessControl];
    }

    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        OSStatus status =  SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
        
        NSString *errorString = [self keychainErrorToString:status];
        NSString *message = [NSString stringWithFormat:@"SecItemAdd status: %@", errorString];
        
        [self printMessage:message inTextView:self.textView];
    });
}

- (void)addItemLeeAsync {
    CFErrorRef error = NULL;
    
    // Should be the secret invalidated when passcode is removed? If not then use kSecAttrAccessibleWhenUnlocked
    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
//                                                                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, // iOS8+ triggeres touchID or passcode based on settings but user can't choose
                                                                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly, // iOS4+
                                                                    kSecAccessControlUserPresence, &error);
    
    if (sacObject == NULL || error != NULL) {
        NSString *errorString = [NSString stringWithFormat:@"SecItemAdd can't create sacObject: %@", error];
        
        self.textView.text = [self.textView.text stringByAppendingString:errorString];
        
        return;
    }
    
    // we want the operation to fail if there is an item which needs authentication so we will use
    // kSecUseNoAuthenticationUI
    NSDictionary *attributes = @{
                                 (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                                 (__bridge id)kSecAttrService: @"SampleService", // service name
                                 (__bridge id)kSecAttrAccount: @"SampleValue", // value name
                                 (__bridge id)kSecValueData: [@"SECRET_PASSWORD_TEXT" dataUsingEncoding:NSUTF8StringEncoding], // value
                                 (__bridge id)kSecUseOperationPrompt: @"Authenticate to access lee's service password",
                                 //(__bridge id)kSecUseNoAuthenticationUI: @YES,
                                 (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject
                                 };
    
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        OSStatus status =  SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
        
        NSString *errorString = [self keychainErrorToString:status];
        NSString *message = [NSString stringWithFormat:@"SecItemAdd status: %@", errorString];
        
        [self printMessage:message inTextView:self.textView];
    });
}

- (void)copyMatchingLeeAsync {
    NSMutableDictionary *query = [@{
                            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrService: @"SampleService", // service name
                            (__bridge id)kSecAttrAccount: @"SampleValue", // value name
                            (__bridge id)kSecReturnData: @YES
                            } mutableCopy];

    if (floor(NSFoundationVersionNumber) > NSFoundationVersionNumber_iOS_7_1)
    {
        [query setObject:@"Authenticate to access lee's service password" forKey:(__bridge id)kSecUseOperationPrompt];
    }
    
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        CFTypeRef dataTypeRef = NULL;
        NSString *message;
        
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &dataTypeRef);
        if (status == errSecSuccess) {
            NSData *resultData = (__bridge_transfer NSData *)dataTypeRef;
            
            NSString *result = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
            
            message = [NSString stringWithFormat:@"Result: %@\n", result];
        }
        else {
            message = [NSString stringWithFormat:@"SecItemCopyMatching status: %@", [self keychainErrorToString:status]];
        }
        
        [self printMessage:message inTextView:self.textView];
    });
}


- (void)deleteItemLeeAsync {
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrService: @"SampleService", // service name
                            (__bridge id)kSecAttrAccount: @"SampleValue" // value name
                            };
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
        
        NSString *errorString = [self keychainErrorToString:status];
        NSString *message = [NSString stringWithFormat:@"SecItemDelete status: %@", errorString];
        
        [super printMessage:message inTextView:self.textView];
    });
}

- (void)copyMatchingAsync {
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrService: @"SampleService",
                            (__bridge id)kSecReturnData: @YES,
                            (__bridge id)kSecUseOperationPrompt: @"Authenticate to access service password",
                            };
    
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        CFTypeRef dataTypeRef = NULL;
        NSString *message;
        
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &dataTypeRef);
        if (status == errSecSuccess) {
            NSData *resultData = (__bridge_transfer NSData *)dataTypeRef;
            
            NSString *result = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
            
            message = [NSString stringWithFormat:@"Result: %@\n", result];
        }
        else {
            message = [NSString stringWithFormat:@"SecItemCopyMatching status: %@", [self keychainErrorToString:status]];
        }
        
        [self printMessage:message inTextView:self.textView];
    });
}

- (void)updateItemAsync {
    NSDictionary *query = @{
                            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                            (__bridge id)kSecAttrService: @"SampleService",
                            (__bridge id)kSecUseOperationPrompt: @"Authenticate to update your password"
                            };
    
    NSData *updatedSecretPasswordTextData = [@"UPDATED_SECRET_PASSWORD_TEXT" dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *changes = @{
                              (__bridge id)kSecValueData: updatedSecretPasswordTextData
                              };
    
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)changes);
        
        NSString *errorString = [self keychainErrorToString:status];
        NSString *message = [NSString stringWithFormat:@"SecItemUpdate status: %@", errorString];
        
        [super printMessage:message inTextView:self.textView];
    });
}

- (void)addItemAsync {
    CFErrorRef error = NULL;
    
    // Should be the secret invalidated when passcode is removed? If not then use kSecAttrAccessibleWhenUnlocked
    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                kSecAccessControlUserPresence, &error);

    if (sacObject == NULL || error != NULL) {
        NSString *errorString = [NSString stringWithFormat:@"SecItemAdd can't create sacObject: %@", error];
        
        self.textView.text = [self.textView.text stringByAppendingString:errorString];
        
        return;
    }
    
    // we want the operation to fail if there is an item which needs authentication so we will use
    // kSecUseNoAuthenticationUI
    NSDictionary *attributes = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"SampleService",
        (__bridge id)kSecValueData: [@"SECRET_PASSWORD_TEXT" dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecUseNoAuthenticationUI: @YES,
        (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject
    };
    
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        OSStatus status =  SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
        
        NSString *errorString = [self keychainErrorToString:status];
        NSString *message = [NSString stringWithFormat:@"SecItemAdd status: %@", errorString];

        [self printMessage:message inTextView:self.textView];
    });
}

- (void)addTouchIDItemAsync {
    CFErrorRef error = NULL;

    // Should be the secret invalidated when passcode is removed? If not then use kSecAttrAccessibleWhenUnlocked
    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                kSecAccessControlTouchIDAny, &error);
    if (sacObject == NULL || error != NULL) {
        NSString *errorString = [NSString stringWithFormat:@"SecItemAdd can't create sacObject: %@", error];
        
        self.textView.text = [self.textView.text stringByAppendingString:errorString];
       
        return;
    }

    /*
        We want the operation to fail if there is an item which needs authentication so we will use
        `kSecUseNoAuthenticationUI`.
    */
    NSData *secretPasswordTextData = [@"SECRET_PASSWORD_TEXT" dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *attributes = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"SampleService",
        (__bridge id)kSecValueData: secretPasswordTextData,
        (__bridge id)kSecUseNoAuthenticationUI: @YES,
        (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject
    };

    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        OSStatus status =  SecItemAdd((__bridge CFDictionaryRef)attributes, nil);

        NSString *message = [NSString stringWithFormat:@"SecItemAdd status: %@", [self keychainErrorToString:status]];

        [self printMessage:message inTextView:self.textView];
    });
}

- (void)addPwdItem {
    CFErrorRef error = NULL;
    
    // Should be the secret invalidated when passcode is removed? If not then use kSecAttrAccessibleWhenUnlocke.
    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                kSecAccessControlTouchIDAny | kSecAccessControlApplicationPassword, &error);
    
    if (sacObject == NULL || error != NULL) {
        NSString *errorString = [NSString stringWithFormat:@"SecItemAdd can't create sacObject: %@", error];
        
        self.textView.text = [self.textView.text stringByAppendingString:errorString];
        
        return;
    }

    LAContext *context = [[LAContext alloc] init];

    [context evaluateAccessControl:sacObject operation:LAAccessControlOperationCreateItem localizedReason:@"Create Item" reply:^(BOOL success, NSError * error) {
        if (success) {
            /*
                We want the operation to fail if there is an item which needs authentication so we will use
                `kSecUseNoAuthenticationUI`.
            */
            NSData *secretPasswordTextData = [@"SECRET_PASSWORD_TEXT" dataUsingEncoding:NSUTF8StringEncoding];
            NSDictionary *attributes = @{
                (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
                (__bridge id)kSecAttrService: @"SampleService",
                (__bridge id)kSecValueData: secretPasswordTextData,
                (__bridge id)kSecUseNoAuthenticationUI: @YES,
                (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject,
                (__bridge id)kSecUseAuthenticationContext: context
            };

            OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, nil);
            NSString *error = [self keychainErrorToString:status];
            NSString *message = [NSString stringWithFormat:@"SecItemAdd status: %@", error];

            [self printMessage:message inTextView:self.textView];
        }
        else {
            [self printMessage:error.description inTextView:self.textView];

            CFRelease(sacObject);
        }
    }];
}

- (void)deleteItemAsync {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"SampleService"
    };
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
        
        NSString *errorString = [self keychainErrorToString:status];
        NSString *message = [NSString stringWithFormat:@"SecItemDelete status: %@", errorString];

        [super printMessage:message inTextView:self.textView];
    });
}

- (void)generateKeyAsync {
    CFErrorRef error = NULL;
    SecAccessControlRef sacObject;

    // Should be the secret invalidated when passcode is removed? If not then use `kSecAttrAccessibleWhenUnlocked`.
    sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                kSecAccessControlTouchIDAny | kSecAccessControlPrivateKeyUsage, &error);

    // Create parameters dictionary for key generation.
    NSDictionary *parameters = @{
        (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeEC,
        (__bridge id)kSecAttrKeySizeInBits: @256,
        (__bridge id)kSecPrivateKeyAttrs: @{
            (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject,
            (__bridge id)kSecAttrIsPermanent: @YES,
            (__bridge id)kSecAttrLabel: @"my-se-key",
        },
    };

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Generate key pair.
        SecKeyRef publicKey, privateKey;
        OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
        NSString *errorString = [self keychainErrorToString:status];
        NSString *message = [NSString stringWithFormat:@"Key generation: %@", errorString];
        [self printMessage:message inTextView:self.textView];

        if (status == errSecSuccess) {
            // In your own code, here is where you'd store/use the keys.

            CFRelease(privateKey);
            CFRelease(publicKey);
        }
    });

}

- (void)useKeyAsync {
    // Query private key object from the keychain.
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
        (__bridge id)kSecAttrLabel: @"my-se-key",
        (__bridge id)kSecReturnRef: @YES,
        (__bridge id)kSecUseOperationPrompt: @"Authenticate to sign data"
    };

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Retrieve the key from the keychain.  No authentication is needed at this point.
        SecKeyRef privateKey;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKey);

        if (status == errSecSuccess) {
            // Sign the data in the digest/digestLength memory block.
            uint8_t signature[128];
            size_t signatureLength = sizeof(signature);
            uint8_t digestData[16];
            size_t digestLength = sizeof(digestData);
            status = SecKeyRawSign(privateKey, kSecPaddingPKCS1, digestData, digestLength, signature, &signatureLength);

            NSString *errorString = [self keychainErrorToString:status];
            NSString *message = [NSString stringWithFormat:@"Key usage: %@", errorString];
            [self printMessage:message inTextView:self.textView];
             
            if (status == errSecSuccess) {
                // In your own code, here is where you'd continue with the signature of the digest.
            }
            
            CFRelease(privateKey);
        }
        else {
            NSString *message = [NSString stringWithFormat:@"Key not found: %@",[self keychainErrorToString:status]];
            
            [self printMessage:message inTextView:self.textView];
        }
    });
}

- (void)deleteKeyAsync {
    NSDictionary *query = @{
        (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
        (__bridge id)kSecClass: (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
        (__bridge id)kSecAttrLabel: @"my-se-key",
        (__bridge id)kSecReturnRef: @YES,
    };

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);

        NSString *message = [NSString stringWithFormat:@"SecItemDelete status: %@", [self keychainErrorToString:status]];

        [self printMessage:message inTextView:self.textView];
    });
}

#pragma mark - Tools

- (NSString *)keychainErrorToString:(OSStatus)error {
    NSString *message = [NSString stringWithFormat:@"%ld", (long)error];
    
    switch (error) {
        case errSecSuccess:
            message = @"success";
            break;

        case errSecDuplicateItem:
            message = @"error item already exists";
            break;
        
        case errSecItemNotFound :
            message = @"error item not found";
            break;
        
        case errSecAuthFailed:
            message = @"error item authentication failed";
            break;

        default:
            break;
    }
    
    return message;
}

@end
