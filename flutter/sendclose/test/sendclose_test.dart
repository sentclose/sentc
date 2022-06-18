import 'package:flutter_test/flutter_test.dart';
import 'package:sendclose/sendclose.dart';
import 'package:sendclose/sendclose_platform_interface.dart';
import 'package:sendclose/sendclose_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockSendclosePlatform 
    with MockPlatformInterfaceMixin
    implements SendclosePlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final SendclosePlatform initialPlatform = SendclosePlatform.instance;

  test('$MethodChannelSendclose is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelSendclose>());
  });

  test('getPlatformVersion', () async {
    Sendclose sendclosePlugin = Sendclose();
    MockSendclosePlatform fakePlatform = MockSendclosePlatform();
    SendclosePlatform.instance = fakePlatform;
  
    expect(await sendclosePlugin.getPlatformVersion(), '42');
  });
}
