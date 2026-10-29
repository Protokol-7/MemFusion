package main

import (
	"embed"
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

// appIcon is embedded so the running window can set its icon at runtime.
// On Linux, Wails only picks up build/appicon.png for packaged bundles, not
// for the live window — the window icon must be provided explicitly here.
//
//go:embed build/appicon.png
var appIcon []byte

func main() {
	// Create an instance of the app structure
	app := NewApp()

	// Create application with options
	err := wails.Run(&options.App{
		Title:     "MemFusion",
		Width:     1280,
		Height:    850,
		MinWidth:  800,
		MinHeight: 640,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 27, G: 38, B: 54, A: 1},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		// Keep the original WebView profile across the executable rename.
		Windows: &windows.Options{
			WebviewUserDataPath: filepath.Join(os.Getenv("APPDATA"), "memforensics-gui.exe"),
		},
		Linux: &linux.Options{
			Icon: appIcon,
			// MUST stay explicit. Wails only applies its GPU workaround
			// (wails#2977) when options.Linux is nil — see
			// internal/frontend/desktop/linux/window.go. Setting Linux at all
			// (e.g. to pass Icon) makes WebviewGpuPolicy default to its zero
			// value, WebviewGpuPolicyOnDemand, which re-enables hardware
			// acceleration and segfaults inside SetupWebview on this
			// webkit2gtk 2.52 + Mesa stack. Pinning it to Never restores the
			// behaviour the app had when Linux was nil.
			WebviewGpuPolicy: linux.WebviewGpuPolicyNever,
		},
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
