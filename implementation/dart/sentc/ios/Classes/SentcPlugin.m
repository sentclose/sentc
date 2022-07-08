#import "SentcPlugin.h"
#if __has_include(<sentc/sentc-Swift.h>)
#import <sentc/sentc-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "sentc-Swift.h"
#endif

@implementation SentcPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftSentcPlugin registerWithRegistrar:registrar];
}
@end
