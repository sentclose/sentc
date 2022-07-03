import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'sendclose_platform_interface.dart';

/// An implementation of [SendclosePlatform] that uses method channels.
class MethodChannelSendclose extends SendclosePlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('sendclose');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
