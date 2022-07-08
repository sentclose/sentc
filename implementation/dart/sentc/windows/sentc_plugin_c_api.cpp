#include "include/sentc/sentc_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "sentc_plugin.h"

void SentcPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  sentc::SentcPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
