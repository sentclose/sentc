#ifndef FLUTTER_PLUGIN_SENTC_PLUGIN_H_
#define FLUTTER_PLUGIN_SENTC_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace sentc {

class SentcPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  SentcPlugin();

  virtual ~SentcPlugin();

  // Disallow copy and assign.
  SentcPlugin(const SentcPlugin&) = delete;
  SentcPlugin& operator=(const SentcPlugin&) = delete;

 private:
  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace sentc

#endif  // FLUTTER_PLUGIN_SENTC_PLUGIN_H_
