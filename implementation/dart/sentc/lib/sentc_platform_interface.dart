import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'sentc_method_channel.dart';

abstract class SentcPlatform extends PlatformInterface {
  /// Constructs a SentcPlatform.
  SentcPlatform() : super(token: _token);

  static final Object _token = Object();

  static SentcPlatform _instance = MethodChannelSentc();

  /// The default instance of [SentcPlatform] to use.
  ///
  /// Defaults to [MethodChannelSentc].
  static SentcPlatform get instance => _instance;
  
  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [SentcPlatform] when
  /// they register themselves.
  static set instance(SentcPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
