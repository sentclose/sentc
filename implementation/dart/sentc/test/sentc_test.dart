import 'package:flutter_test/flutter_test.dart';
import 'package:sentc/sentc.dart';
import 'package:sentc/sentc_platform_interface.dart';
import 'package:sentc/sentc_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockSentcPlatform 
    with MockPlatformInterfaceMixin
    implements SentcPlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final SentcPlatform initialPlatform = SentcPlatform.instance;

  test('$MethodChannelSentc is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelSentc>());
  });

  test('getPlatformVersion', () async {
    Sentc sentcPlugin = Sentc();
    MockSentcPlatform fakePlatform = MockSentcPlatform();
    SentcPlatform.instance = fakePlatform;
  
    expect(await sentcPlugin.getPlatformVersion(), '42');
  });
}
