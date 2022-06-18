#import "SendclosePlugin.h"
#if __has_include(<sendclose/sendclose-Swift.h>)
#import <sendclose/sendclose-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "sendclose-Swift.h"
#endif

@implementation SendclosePlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftSendclosePlugin registerWithRegistrar:registrar];
}
@end
