#include "include/sendclose/sendclose_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "sendclose_plugin.h"

void SendclosePluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  sendclose::SendclosePlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
