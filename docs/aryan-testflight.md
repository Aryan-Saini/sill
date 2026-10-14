# Publish Aryan's fork to TestFlight

The fork uses bundle ID `com.aryansaini.sill` on the Syncafy Inc Apple team `NQGS32ZLHW`. The bundle ID is registered. The upstream license and attribution remain intact.

## Create the app record

Apple requires this step on the App Store Connect website. Its public API cannot create app records. You can use Safari on your phone.

1. Open https://appstoreconnect.apple.com/apps and select Syncafy Inc.
2. Select the plus button, then New App.
3. Select iOS, enter `Sill Aryan` as the name, and select English as the primary language.
4. Select bundle ID `com.aryansaini.sill` and enter `sill-aryan` as the SKU.
5. Create the app.

If the name is unavailable, choose another name. Keep the bundle ID and SKU above.

## Build and upload

The current source requires Xcode 27.1 or later for its iOS 27.1 foldable APIs. This Mac currently has Xcode 27.0. Install a compatible Xcode without changing the Mac's global developer directory, then use `DEVELOPER_DIR` for this build.

Run from the repository root with the existing App Store Connect API key outside the repository:

```bash
DEVELOPER_DIR=/path/to/Xcode.app/Contents/Developer Scripts/release-ios.sh --sign-at-export --upload --api-key ~/.secrets/AuthKey_ZMH4SHGZ3B.p8 --api-issuer 78fbf75f-f35b-4087-a6ba-e0ba7f1c65b7
```

After Apple processes the build, assign it to a TestFlight group. A public invitation link requires an external group and Apple's beta approval. No TestFlight build has been uploaded yet.

## Connect while away

The published upstream iOS app is already free at https://apps.apple.com/us/app/sill-mac-streaming/id6816359860. It can connect to the upstream Mac app without this fork.

Sill requires Screen Recording and Accessibility permission on the Mac, one-time device pairing, and Remote Access enabled for connections through a VPN such as Tailscale. The Mac must be awake. The fork does not bypass these permissions or the Mac login screen.
