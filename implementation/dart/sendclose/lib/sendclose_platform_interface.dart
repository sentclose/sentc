import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'sendclose_method_channel.dart';

abstract class SendclosePlatform extends PlatformInterface {
  /// Constructs a SendclosePlatform.
  SendclosePlatform() : super(token: _token);

  static final Object _token = Object();

  static SendclosePlatform _instance = MethodChannelSendclose();

  /// The default instance of [SendclosePlatform] to use.
  ///
  /// Defaults to [MethodChannelSendclose].
  static SendclosePlatform get instance => _instance;
  
  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [SendclosePlatform] when
  /// they register themselves.
  static set instance(SendclosePlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
