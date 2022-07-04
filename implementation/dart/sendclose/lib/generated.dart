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
  Future<String> registerTestFull({dynamic hint});

  FlutterRustBridgeTaskConstMeta get kRegisterTestFullConstMeta;

  Future<String> register({required String password, dynamic hint});

  FlutterRustBridgeTaskConstMeta get kRegisterConstMeta;

  Future<String> prepareLogin(
      {required String password,
      required String saltString,
      required String derivedEncryptionKeyAlg,
      dynamic hint});

  FlutterRustBridgeTaskConstMeta get kPrepareLoginConstMeta;

  Future<String> doneLogin(
      {required String masterKeyEncryption,
      required String serverOutput,
      dynamic hint});

  FlutterRustBridgeTaskConstMeta get kDoneLoginConstMeta;
}

class SendcloseFlutterImpl extends FlutterRustBridgeBase<SendcloseFlutterWire>
    implements SendcloseFlutter {
  factory SendcloseFlutterImpl(ffi.DynamicLibrary dylib) =>
      SendcloseFlutterImpl.raw(SendcloseFlutterWire(dylib));

  SendcloseFlutterImpl.raw(SendcloseFlutterWire inner) : super(inner);

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

  Future<String> register({required String password, dynamic hint}) =>
      executeNormal(FlutterRustBridgeTask(
        callFfi: (port_) =>
            inner.wire_register(port_, _api2wire_String(password)),
        parseSuccessData: _wire2api_String,
        constMeta: kRegisterConstMeta,
        argValues: [password],
        hint: hint,
      ));

  FlutterRustBridgeTaskConstMeta get kRegisterConstMeta =>
      const FlutterRustBridgeTaskConstMeta(
        debugName: "register",
        argNames: ["password"],
      );

  Future<String> prepareLogin(
          {required String password,
          required String saltString,
          required String derivedEncryptionKeyAlg,
          dynamic hint}) =>
      executeNormal(FlutterRustBridgeTask(
        callFfi: (port_) => inner.wire_prepare_login(
            port_,
            _api2wire_String(password),
            _api2wire_String(saltString),
            _api2wire_String(derivedEncryptionKeyAlg)),
        parseSuccessData: _wire2api_String,
        constMeta: kPrepareLoginConstMeta,
        argValues: [password, saltString, derivedEncryptionKeyAlg],
        hint: hint,
      ));

  FlutterRustBridgeTaskConstMeta get kPrepareLoginConstMeta =>
      const FlutterRustBridgeTaskConstMeta(
        debugName: "prepare_login",
        argNames: ["password", "saltString", "derivedEncryptionKeyAlg"],
      );

  Future<String> doneLogin(
          {required String masterKeyEncryption,
          required String serverOutput,
          dynamic hint}) =>
      executeNormal(FlutterRustBridgeTask(
        callFfi: (port_) => inner.wire_done_login(
            port_,
            _api2wire_String(masterKeyEncryption),
            _api2wire_String(serverOutput)),
        parseSuccessData: _wire2api_String,
        constMeta: kDoneLoginConstMeta,
        argValues: [masterKeyEncryption, serverOutput],
        hint: hint,
      ));

  FlutterRustBridgeTaskConstMeta get kDoneLoginConstMeta =>
      const FlutterRustBridgeTaskConstMeta(
        debugName: "done_login",
        argNames: ["masterKeyEncryption", "serverOutput"],
      );

  // Section: api2wire
  ffi.Pointer<wire_uint_8_list> _api2wire_String(String raw) {
    return _api2wire_uint_8_list(utf8.encoder.convert(raw));
  }

  int _api2wire_u8(int raw) {
    return raw;
  }

  ffi.Pointer<wire_uint_8_list> _api2wire_uint_8_list(Uint8List raw) {
    final ans = inner.new_uint_8_list(raw.length);
    ans.ref.ptr.asTypedList(raw.length).setAll(0, raw);
    return ans;
  }

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

  void wire_register(
    int port_,
    ffi.Pointer<wire_uint_8_list> password,
  ) {
    return _wire_register(
      port_,
      password,
    );
  }

  late final _wire_registerPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(
              ffi.Int64, ffi.Pointer<wire_uint_8_list>)>>('wire_register');
  late final _wire_register = _wire_registerPtr
      .asFunction<void Function(int, ffi.Pointer<wire_uint_8_list>)>();

  void wire_prepare_login(
    int port_,
    ffi.Pointer<wire_uint_8_list> password,
    ffi.Pointer<wire_uint_8_list> salt_string,
    ffi.Pointer<wire_uint_8_list> derived_encryption_key_alg,
  ) {
    return _wire_prepare_login(
      port_,
      password,
      salt_string,
      derived_encryption_key_alg,
    );
  }

  late final _wire_prepare_loginPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(
              ffi.Int64,
              ffi.Pointer<wire_uint_8_list>,
              ffi.Pointer<wire_uint_8_list>,
              ffi.Pointer<wire_uint_8_list>)>>('wire_prepare_login');
  late final _wire_prepare_login = _wire_prepare_loginPtr.asFunction<
      void Function(int, ffi.Pointer<wire_uint_8_list>,
          ffi.Pointer<wire_uint_8_list>, ffi.Pointer<wire_uint_8_list>)>();

  void wire_done_login(
    int port_,
    ffi.Pointer<wire_uint_8_list> master_key_encryption,
    ffi.Pointer<wire_uint_8_list> server_output,
  ) {
    return _wire_done_login(
      port_,
      master_key_encryption,
      server_output,
    );
  }

  late final _wire_done_loginPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(ffi.Int64, ffi.Pointer<wire_uint_8_list>,
              ffi.Pointer<wire_uint_8_list>)>>('wire_done_login');
  late final _wire_done_login = _wire_done_loginPtr.asFunction<
      void Function(
          int, ffi.Pointer<wire_uint_8_list>, ffi.Pointer<wire_uint_8_list>)>();

  ffi.Pointer<wire_uint_8_list> new_uint_8_list(
    int len,
  ) {
    return _new_uint_8_list(
      len,
    );
  }

  late final _new_uint_8_listPtr = _lookup<
      ffi.NativeFunction<
          ffi.Pointer<wire_uint_8_list> Function(
              ffi.Int32)>>('new_uint_8_list');
  late final _new_uint_8_list = _new_uint_8_listPtr
      .asFunction<ffi.Pointer<wire_uint_8_list> Function(int)>();

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

class wire_uint_8_list extends ffi.Struct {
  external ffi.Pointer<ffi.Uint8> ptr;

  @ffi.Int32()
  external int len;
}

typedef DartPostCObjectFnType = ffi.Pointer<
    ffi.NativeFunction<ffi.Uint8 Function(DartPort, ffi.Pointer<ffi.Void>)>>;
typedef DartPort = ffi.Int64;