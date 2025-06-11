import 'dart:io';
import 'package:flutter/material.dart';
import 'package:webview_windows/webview_windows.dart';

void main() async {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});
  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      title: 'Threat Detection Dashboard',
      home: DashboardLauncher(),
    );
  }
}

class DashboardLauncher extends StatefulWidget {
  const DashboardLauncher({super.key});
  @override
  State<DashboardLauncher> createState() => _DashboardLauncherState();
}

class _DashboardLauncherState extends State<DashboardLauncher> {
  final controller = WebviewController();

  @override
  void initState() {
    super.initState();
    _startServerAndLoad();
  }

  Future<void> _startServerAndLoad() async {
    // Start server.py
    Process.start('python', ['Server.py'], workingDirectory: r'D:\.') // Make sure this is correct
        .then((process) {
      print("Server started.");
    }).catchError((e) {
      print("Failed to start server: $e");
    });

    // Initialize webview
    await controller.initialize();
    await controller.loadUrl('http://127.0.0.1:8000');

    setState(() {}); // Refresh UI to show the view
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("Network Threat Dashboard")),
      body: controller.value.isInitialized
          ? Webview(controller)
          : const Center(child: CircularProgressIndicator()),
    );
  }
}
