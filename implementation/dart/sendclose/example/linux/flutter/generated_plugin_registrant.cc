//
//  Generated file. Do not edit.
//

// clang-format off

#include "generated_plugin_registrant.h"

#include <sendclose/sendclose_plugin.h>

void fl_register_plugins(FlPluginRegistry* registry) {
  g_autoptr(FlPluginRegistrar) sendclose_registrar =
      fl_plugin_registry_get_registrar_for_plugin(registry, "SendclosePlugin");
  sendclose_plugin_register_with_registrar(sendclose_registrar);
}
