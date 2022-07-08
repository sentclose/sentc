import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'sentc_platform_interface.dart';

/// An implementation of [SentcPlatform] that uses method channels.
class MethodChannelSentc extends SentcPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('sentc');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
