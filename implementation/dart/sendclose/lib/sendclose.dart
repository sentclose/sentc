import 'dart:ffi';
import 'dart:io';

import 'package:sendclose/generated.dart';

import 'sendclose_platform_interface.dart';

class Sendclose {
  final SendcloseFlutterImpl api;

  const Sendclose._(this.api);

  Future<String?> getPlatformVersion() {
    return SendclosePlatform.instance.getPlatformVersion();
  }

  factory Sendclose()
  {
    const base = "sendclose_flutter";
    final path = Platform.isWindows ? "$base.dll" : "lib$base.so";
    late final dylib = Platform.isIOS
        ? DynamicLibrary.process()
        : Platform.isMacOS
        ? DynamicLibrary.executable()
        : DynamicLibrary.open(path);

    final SendcloseFlutterImpl api = SendcloseFlutterImpl(dylib);
    return Sendclose._(api);
  }

  Future<String> register(String password)
  {
    return api.register(password: password);
  }

  Future<String> registerTest()
  {
    return api.registerTestFull();
  }
}
