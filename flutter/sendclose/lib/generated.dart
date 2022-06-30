// AUTO GENERATED FILE, DO NOT EDIT.
// Generated by `flutter_rust_bridge`.

// ignore_for_file: non_constant_identifier_names, unused_element, duplicate_ignore, directives_ordering, curly_braces_in_flow_control_structures, unnecessary_lambdas, slash_for_doc_comments, prefer_const_literals_to_create_immutables, implicit_dynamic_list_literal, duplicate_import, unused_import, prefer_single_quotes, prefer_const_constructors, use_super_parameters, always_use_package_imports

import 'dart:convert';
import 'dart:typed_data';

import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'dart:ffi' as ffi;

abstract class SendcloseFlutter {
  Future<String> aesTest({dynamic hint});

  FlutterRustBridgeTaskConstMeta get kAesTestConstMeta;

  Future<String> edTest({dynamic hint});

  FlutterRustBridgeTaskConstMeta get kEdTestConstMeta;

  Future<String> argonTest({dynamic hint});

  FlutterRustBridgeTaskConstMeta get kArgonTestConstMeta;

  Future<String> signTest({dynamic hint});

  FlutterRustBridgeTaskConstMeta get kSignTestConstMeta;

  Future<String> registerTestFull({dynamic hint});

  FlutterRustBridgeTaskConstMeta get kRegisterTestFullConstMeta;
}

class SendcloseFlutterImpl extends FlutterRustBridgeBase<SendcloseFlutterWire>
    implements SendcloseFlutter {
  factory SendcloseFlutterImpl(ffi.DynamicLibrary dylib) =>
      SendcloseFlutterImpl.raw(SendcloseFlutterWire(dylib));

  SendcloseFlutterImpl.raw(SendcloseFlutterWire inner) : super(inner);

  Future<String> aesTest({dynamic hint}) => executeNormal(FlutterRustBridgeTask(
        callFfi: (port_) => inner.wire_aes_test(port_),
        parseSuccessData: _wire2api_String,
        constMeta: kAesTestConstMeta,
        argValues: [],
        hint: hint,
      ));

  FlutterRustBridgeTaskConstMeta get kAesTestConstMeta =>
      const FlutterRustBridgeTaskConstMeta(
        debugName: "aes_test",
        argNames: [],
      );

  Future<String> edTest({dynamic hint}) => executeNormal(FlutterRustBridgeTask(
        callFfi: (port_) => inner.wire_ed_test(port_),
        parseSuccessData: _wire2api_String,
        constMeta: kEdTestConstMeta,
        argValues: [],
        hint: hint,
      ));

  FlutterRustBridgeTaskConstMeta get kEdTestConstMeta =>
      const FlutterRustBridgeTaskConstMeta(
        debugName: "ed_test",
        argNames: [],
      );

  Future<String> argonTest({dynamic hint}) =>
      executeNormal(FlutterRustBridgeTask(
        callFfi: (port_) => inner.wire_argon_test(port_),
        parseSuccessData: _wire2api_String,
        constMeta: kArgonTestConstMeta,
        argValues: [],
        hint: hint,
      ));

  FlutterRustBridgeTaskConstMeta get kArgonTestConstMeta =>
      const FlutterRustBridgeTaskConstMeta(
        debugName: "argon_test",
        argNames: [],
      );

  Future<String> signTest({dynamic hint}) =>
      executeNormal(FlutterRustBridgeTask(
        callFfi: (port_) => inner.wire_sign_test(port_),
        parseSuccessData: _wire2api_String,
        constMeta: kSignTestConstMeta,
        argValues: [],
        hint: hint,
      ));

  FlutterRustBridgeTaskConstMeta get kSignTestConstMeta =>
      const FlutterRustBridgeTaskConstMeta(
        debugName: "sign_test",
        argNames: [],
      );

  Future<String> registerTestFull({dynamic hint}) =>
      executeNormal(FlutterRustBridgeTask(
        callFfi: (port_) => inner.wire_register_test_full(port_),
        parseSuccessData: _wire2api_String,
        constMeta: kRegisterTestFullConstMeta,
        argValues: [],
        hint: hint,
      ));

  FlutterRustBridgeTaskConstMeta get kRegisterTestFullConstMeta =>
      const FlutterRustBridgeTaskConstMeta(
        debugName: "register_test_full",
        argNames: [],
      );

  // Section: api2wire

  // Section: api_fill_to_wire

}

// Section: wire2api
String _wire2api_String(dynamic raw) {
  return raw as String;
}

int _wire2api_u8(dynamic raw) {
  return raw as int;
}

Uint8List _wire2api_uint_8_list(dynamic raw) {
  return raw as Uint8List;
}

// ignore_for_file: camel_case_types, non_constant_identifier_names, avoid_positional_boolean_parameters, annotate_overrides, constant_identifier_names

// AUTO GENERATED FILE, DO NOT EDIT.
//
// Generated by `package:ffigen`.

/// generated by flutter_rust_bridge
class SendcloseFlutterWire implements FlutterRustBridgeWireBase {
  /// Holds the symbol lookup function.
  final ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
      _lookup;

  /// The symbols are looked up in [dynamicLibrary].
  SendcloseFlutterWire(ffi.DynamicLibrary dynamicLibrary)
      : _lookup = dynamicLibrary.lookup;

  /// The symbols are looked up with [lookup].
  SendcloseFlutterWire.fromLookup(
      ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
          lookup)
      : _lookup = lookup;

  void wire_aes_test(
    int port_,
  ) {
    return _wire_aes_test(
      port_,
    );
  }

  late final _wire_aes_testPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Int64)>>(
          'wire_aes_test');
  late final _wire_aes_test =
      _wire_aes_testPtr.asFunction<void Function(int)>();

  void wire_ed_test(
    int port_,
  ) {
    return _wire_ed_test(
      port_,
    );
  }

  late final _wire_ed_testPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Int64)>>('wire_ed_test');
  late final _wire_ed_test = _wire_ed_testPtr.asFunction<void Function(int)>();

  void wire_argon_test(
    int port_,
  ) {
    return _wire_argon_test(
      port_,
    );
  }

  late final _wire_argon_testPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Int64)>>(
          'wire_argon_test');
  late final _wire_argon_test =
      _wire_argon_testPtr.asFunction<void Function(int)>();

  void wire_sign_test(
    int port_,
  ) {
    return _wire_sign_test(
      port_,
    );
  }

  late final _wire_sign_testPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Int64)>>(
          'wire_sign_test');
  late final _wire_sign_test =
      _wire_sign_testPtr.asFunction<void Function(int)>();

  void wire_register_test_full(
    int port_,
  ) {
    return _wire_register_test_full(
      port_,
    );
  }

  late final _wire_register_test_fullPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Int64)>>(
          'wire_register_test_full');
  late final _wire_register_test_full =
      _wire_register_test_fullPtr.asFunction<void Function(int)>();

  void free_WireSyncReturnStruct(
    WireSyncReturnStruct val,
  ) {
    return _free_WireSyncReturnStruct(
      val,
    );
  }

  late final _free_WireSyncReturnStructPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(WireSyncReturnStruct)>>(
          'free_WireSyncReturnStruct');
  late final _free_WireSyncReturnStruct = _free_WireSyncReturnStructPtr
      .asFunction<void Function(WireSyncReturnStruct)>();

  void store_dart_post_cobject(
    DartPostCObjectFnType ptr,
  ) {
    return _store_dart_post_cobject(
      ptr,
    );
  }

  late final _store_dart_post_cobjectPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(DartPostCObjectFnType)>>(
          'store_dart_post_cobject');
  late final _store_dart_post_cobject = _store_dart_post_cobjectPtr
      .asFunction<void Function(DartPostCObjectFnType)>();
}

typedef DartPostCObjectFnType = ffi.Pointer<
    ffi.NativeFunction<ffi.Uint8 Function(DartPort, ffi.Pointer<ffi.Void>)>>;
typedef DartPort = ffi.Int64;
