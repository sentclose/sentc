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
    final path = Platform.isWindows ? "../../../target/release/$base.dll" : "lib$base.so";
    late final dylib = Platform.isIOS
        ? DynamicLibrary.process()
        : Platform.isMacOS
        ? DynamicLibrary.executable()
        : DynamicLibrary.open(path);

    final SendcloseFlutterImpl api = SendcloseFlutterImpl(dylib);
    return Sendclose._(api);
  }

  Future<String> aesTest()
  {
    return api.aesTest();
  }

  Future<String> edTest()
  {
    return api.edTest();
  }

  Future<String> argonTest()
  {
    return api.argonTest();
  }

  Future<String> signTest()
  {
    return api.signTest();
  }
}
