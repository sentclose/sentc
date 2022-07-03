import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sendclose/sendclose_method_channel.dart';

void main() {
  MethodChannelSendclose platform = MethodChannelSendclose();
  const MethodChannel channel = MethodChannel('sendclose');

  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    channel.setMockMethodCallHandler((MethodCall methodCall) async {
      return '42';
    });
  });

  tearDown(() {
    channel.setMockMethodCallHandler(null);
  });

  test('getPlatformVersion', () async {
    expect(await platform.getPlatformVersion(), '42');
  });
}
