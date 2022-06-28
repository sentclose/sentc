import 'package:flutter/material.dart';
import 'dart:async';

import 'package:sendclose/sendclose.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final _sendclosePlugin = Sendclose();

  late Future<void> aes_test;
  late Future<void> ecdh_test;
  late Future<void> argon_test;
  late Future<void> sign_test;

  @override
  void initState() {
    super.initState();

    aes_test = _sendclosePlugin.aesTest();
    ecdh_test = _sendclosePlugin.edTest();
    argon_test = _sendclosePlugin.argonTest();
    sign_test = _sendclosePlugin.signTest();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: Center(
          child: Column(
            children: <Widget>[
              FutureBuilder<List<dynamic>>(
                  future: Future.wait([aes_test]),
                  builder: (context, snap) {
                    final data = snap.data;
                    if (data == null) {
                      return const Text("Loading");
                    }
                    return Text(
                      '${data[0]}',
                      style: Theme.of(context).textTheme.headline4,
                    );
                  }),
              FutureBuilder<List<dynamic>>(
                  future: Future.wait([ecdh_test]),
                  builder: (context, snap) {
                    final data = snap.data;
                    if (data == null) {
                      return const Text("Loading");
                    }
                    return Text(
                      '${data[0]}',
                      style: Theme.of(context).textTheme.headline4,
                    );
                  }),
              FutureBuilder<List<dynamic>>(
                  future: Future.wait([argon_test]),
                  builder: (context, snap) {
                    final data = snap.data;
                    if (data == null) {
                      return const Text("Loading");
                    }
                    return Text(
                      '${data[0]}',
                      style: Theme.of(context).textTheme.headline4,
                    );
                  }),
              FutureBuilder<List<dynamic>>(
                  future: Future.wait([sign_test]),
                  builder: (context, snap) {
                    final data = snap.data;
                    if (data == null) {
                      return const Text("Loading");
                    }
                    return Text(
                      '${data[0]}',
                      style: Theme.of(context).textTheme.headline4,
                    );
                  }),
            ],
          ),

        ),
      ),
    );
  }
}
