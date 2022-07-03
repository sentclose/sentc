// In order to *not* need this ignore, consider extracting the "web" version
// of your plugin as a separate package, instead of inlining it in the same
// package as the core of your plugin.
// ignore: avoid_web_libraries_in_flutter
import 'dart:html' as html show window;

import 'package:flutter_web_plugins/flutter_web_plugins.dart';

import 'sendclose_platform_interface.dart';

/// A web implementation of the SendclosePlatform of the Sendclose plugin.
class SendcloseWeb extends SendclosePlatform {
  /// Constructs a SendcloseWeb
  SendcloseWeb();

  static void registerWith(Registrar registrar) {
    SendclosePlatform.instance = SendcloseWeb();
  }

  /// Returns a [String] containing the version of the platform.
  @override
  Future<String?> getPlatformVersion() async {
    final version = html.window.navigator.userAgent;
    return version;
  }
}
