// SPDX-License-Identifier: GPL-3.0-or-later
import XCTest

final class ExportRunUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
        XCUIDevice.shared.orientation = .portrait
    }

    private func launch(_ arguments: [String] = []) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = arguments
        app.launch()
        return app
    }

    private func request(_ app: XCUIApplication, controls: Bool = false, baseline: Bool = false) {
        let menu = app.buttons[controls ? "controls-menu" : "library-menu"]
        XCTAssertTrue(menu.waitForExistence(timeout: 10))
        menu.tap()
        let button = app.buttons[baseline ? "Export Run Diagnostics" : "madeira.export-run"]
        XCTAssertTrue(button.waitForExistence(timeout: 5))
        button.tap()
    }

    private func event(_ text: String, app: XCUIApplication, timeout: TimeInterval = 10) {
        let value = app.staticTexts["host.events"].firstMatch
        let match = NSPredicate(format: "label CONTAINS %@", text)
        expectation(for: match, evaluatedWith: value)
        waitForExpectations(timeout: timeout)
    }

    private func saveToFiles(_ app: XCUIApplication) -> XCUIElement {
        let predicate = NSPredicate(format: "label == %@", "Save to Files")
        return app.descendants(matching: .any).matching(predicate).firstMatch
    }

    private func confirmNativeShare(_ app: XCUIApplication) {
        XCTAssertTrue(saveToFiles(app).waitForExistence(timeout: 15), "Native Files sharing action must actually be visible")
        let shot = XCTAttachment(screenshot: app.screenshot())
        shot.name = "Owned host native share interface"; shot.lifetime = .keepAlways
        add(shot)
    }

    private func openNativeFiles(_ app: XCUIApplication) {
        let action = saveToFiles(app)
        XCTAssertTrue(action.waitForExistence(timeout: 8))
        for _ in 0..<4 where !action.isHittable { app.swipeUp() }
        XCTAssertTrue(action.isHittable, "Native Files action must receive a real tap")
        action.tap()
    }

    private func preserveOwnedPickerState(_ app: XCUIApplication, context: String = "picker-not-ready") {
        // Fresh simulator, owned test host, and Apple's empty system picker:
        // no game, Steam account, or user Files container is opened here.
        print("OWNED_EXPORT_UI_CAPTURE_CONTEXT \(context)")
        for (name, application) in [
            ("host", app),
            ("springboard", XCUIApplication(bundleIdentifier: "com.apple.springboard")),
            ("documents", XCUIApplication(bundleIdentifier: "com.apple.DocumentsApp")),
            ("save-extension", XCUIApplication(bundleIdentifier: "com.apple.DocumentManagerUICore.SaveToFiles")),
        ] {
            print("OWNED_EXPORT_UI_HIERARCHY_BEGIN \(name) state=\(application.state.rawValue)")
            if application.state != .notRunning { print(String(application.debugDescription.prefix(20000))) }
            print("OWNED_EXPORT_UI_HIERARCHY_END \(name)")
        }
        let screenshot = XCUIScreen.main.screenshot()
        let attachment = XCTAttachment(screenshot: screenshot)
        attachment.name = "Owned host after native Files action"; attachment.lifetime = .keepAlways
        add(attachment)
        // Also preserve this small, owned UI image in the textual CI log when
        // the artifact-download service cannot materialize xcresult locally.
        let bytes = screenshot.pngRepresentation
        if bytes.count <= 512 * 1024 {
            print("OWNED_EXPORT_UI_SCREENSHOT_BASE64_BEGIN")
            print(bytes.base64EncodedString())
            print("OWNED_EXPORT_UI_SCREENSHOT_BASE64_END")
        }
    }

    private func dismissNativeShare(_ app: XCUIApplication, request: Int = 1) {
        // Current iOS exposes a Close button; older simulator releases use
        // Cancel. These are actual native controls, never a mocked completion.
        let close = app.buttons["Close"].firstMatch
        let cancel = app.buttons["Cancel"].firstMatch
        if close.waitForExistence(timeout: 3) { close.tap() }
        else if cancel.exists { cancel.tap() }
        else {
            // Public XCTest gesture mirrors dragging the native sheet away.
            app.swipeDown()
        }
        event("event=share-finished request=\(request)", app: app)
        event("event=share-presented request=\(request)", app: app)
    }

    private func saveInOwnedDocuments(_ app: XCUIApplication) {
        // The system Files interface must open and perform its own copy into
        // the isolated host's Documents folder; the archive factory cannot
        // write the destination that the collector subsequently verifies.
        // Save to Files runs in Apple's native extension process. Query its
        // actual picker, rather than requiring a remote button to be included
        // in the host application's accessibility query on every iOS release.
        let files = XCUIApplication(bundleIdentifier: "com.apple.DocumentManagerUICore.SaveToFiles")
        XCTAssertTrue(files.wait(for: .runningForeground, timeout: 30), "Apple's Files extension must become foreground")
        // A cold simulator's remote Files provider was still initializing
        // after the old ten-second wait. Its later full AX snapshot showed
        // this exact Save control; wait for readiness and use a complete query.
        let save = files.buttons.matching(identifier: "DOCPicker.actionButton").element(boundBy: 0)
        let pickerOpened = save.waitForExistence(timeout: 45)
        if !pickerOpened { preserveOwnedPickerState(app) }
        XCTAssertTrue(pickerOpened, "Native Files destination picker must open")
        XCTAssertEqual(save.label, "Save")
        XCTAssertTrue(files.otherElements["Browse View (Picker)"].firstMatch.exists)
        let picker = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        picker.name = "Owned host native Files destination picker"; picker.lifetime = .keepAlways
        add(picker)
        preserveOwnedPickerState(app, context: "native-picker-before-owned-folder")
        // FileProvider's first catalog is asynchronous and its default
        // location can differ. Select the observed local provider explicitly;
        // the owned folder's item count and ', Container' decoration are not
        // part of its identity.
        let localStorage = files.cells.matching(identifier: "DOC.sidebar.item.On My iPhone").element(boundBy: 0)
        let localReady = localStorage.waitForExistence(timeout: 30)
        if !localReady { preserveOwnedPickerState(app, context: "local-provider-not-ready") }
        XCTAssertTrue(localReady); localStorage.tap()
        let ownedFolder = files.cells.matching(NSPredicate(
            format: "label BEGINSWITH %@ OR identifier BEGINSWITH %@", "Run Export Host", "Run Export Host"
        )).element(boundBy: 0)
        let folderReady = ownedFolder.waitForExistence(timeout: 30)
        if !folderReady { preserveOwnedPickerState(app, context: "owned-folder-not-ready") }
        XCTAssertTrue(folderReady)
        // The observed cell spans both its folder icon and a tall filename
        // area. Its center tap left the picker at On My iPhone. Tap the actual
        // observed icon, then retain the strict destination/readback checks.
        let folderIcon = ownedFolder.images.element(boundBy: 0)
        if folderIcon.waitForExistence(timeout: 5) && folderIcon.isHittable { folderIcon.tap() }
        else { ownedFolder.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.25)).tap() }
        // FileProvider navigation continues after the tap returns. Saving
        // while its previous root is still active can select On My iPhone
        // rather than this app's Documents. Prove the destination first.
        let destination = files.otherElements.matching(identifier:
            "DOC.browsingRoot Source: com.apple.FileProvider.LocalStorage, Title: Run Export Host"
        ).element(boundBy: 0)
        let destinationReady = destination.waitForExistence(timeout: 30) ||
            files.navigationBars.staticTexts["Run Export Host"].firstMatch.exists
        if !destinationReady { preserveOwnedPickerState(app, context: "owned-folder-navigation-pending") }
        XCTAssertTrue(destinationReady, "The actual native destination must be the owned host folder")
        let ownEventFile = files.cells.matching(NSPredicate(
            format: "label BEGINSWITH %@ OR identifier BEGINSWITH %@", "run-export-events-", "run-export-events-"
        )).element(boundBy: 0)
        let currentDocumentsVisible = ownEventFile.waitForExistence(timeout: 30)
        preserveOwnedPickerState(app, context: "owned-documents-before-native-save")
        XCTAssertTrue(currentDocumentsVisible, "The current host's actual Documents event file must be visible before saving")
        XCTAssertTrue(save.isEnabled); XCTAssertTrue(save.isHittable); save.tap()
        preserveOwnedPickerState(app, context: "immediately-after-native-save")
        let completion = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "label CONTAINS %@", "event=share-finished request=1 completed=1"),
            object: app.staticTexts["host.events"].firstMatch)
        let completed = XCTWaiter.wait(for: [completion], timeout: 20) == .completed
        if !completed { preserveOwnedPickerState(app, context: "after-native-completion-timeout") }
        XCTAssertTrue(completed, "Native Save must report its actual successful activity completion")
    }

    func testActiveLandscapeExportSurvivesOriginDestructionAndOpensFiles() throws {
        XCUIDevice.shared.orientation = .landscapeLeft
        let app = launch(["--active-game", "--drop-origin"])
        XCTAssertGreaterThan(app.frame.width, app.frame.height, "The actual host must be in landscape")
        request(app, controls: true)
        confirmNativeShare(app)
        openNativeFiles(app)
        saveInOwnedDocuments(app)
        XCTAssertTrue(app.buttons["library-menu"].waitForExistence(timeout: 8))
        XCTAssertTrue(app.staticTexts["host.session"].firstMatch.label.contains("session-ended"))
        XCTAssertTrue(app.staticTexts["host.key-window"].firstMatch.label.contains("library"))
        // Export again after the game controls disappeared, using the same
        // application-lifetime coordinator and a real native activity.
        request(app)
        XCTAssertTrue(saveToFiles(app).waitForExistence(timeout: 5))
        dismissNativeShare(app, request: 2)
        event("event=share-presented request=2", app: app)
    }

    func testStockPrimaryWindowFilesSaveControl() throws {
        XCUIDevice.shared.orientation = .landscapeLeft
        let app = launch(["--stock-control"])
        XCTAssertGreaterThan(app.frame.width, app.frame.height)
        let button = app.buttons["stock-export"]
        XCTAssertTrue(button.waitForExistence(timeout: 10)); button.tap()
        confirmNativeShare(app)
        openNativeFiles(app)
        saveInOwnedDocuments(app)
        XCTAssertTrue(button.waitForExistence(timeout: 8))
        XCTAssertTrue(app.staticTexts["host.key-window"].firstMatch.label.contains("library"))
        // Match the original case's second producer invocation and real cancel;
        // source-file reuse is deliberately unchanged for this comparison.
        button.tap()
        confirmNativeShare(app)
        dismissNativeShare(app, request: 2)
    }

    func testEndedSessionExportAndNativeCancellationRestoreWindow() throws {
        XCUIDevice.shared.orientation = .portrait
        let app = launch()
        request(app)
        confirmNativeShare(app)
        dismissNativeShare(app)
        XCTAssertTrue(app.staticTexts["host.key-window"].firstMatch.label.contains("library"))
        request(app)
        XCTAssertTrue(saveToFiles(app).waitForExistence(timeout: 15))
        dismissNativeShare(app, request: 2)
        event("event=share-presented request=2", app: app)
    }

    func testActiveControlsRemainUsableAfterNativeShareCancel() throws {
        let app = launch(["--active-game"])
        request(app, controls: true)
        confirmNativeShare(app)
        dismissNativeShare(app)
        XCTAssertTrue(app.staticTexts["host.key-window"].firstMatch.label.contains("controls"))
        let end = app.buttons["end-controls"]
        XCTAssertTrue(end.waitForExistence(timeout: 5)); end.tap()
        XCTAssertTrue(app.buttons["library-menu"].waitForExistence(timeout: 5))
    }

    func testArchiveFailureShowsUsefulNativeAlertAndCanRetry() throws {
        let app = launch(["--fail-archive"])
        request(app)
        let alert = app.alerts["Run export failed"]
        XCTAssertTrue(alert.waitForExistence(timeout: 10))
        XCTAssertTrue(alert.staticTexts.matching(NSPredicate(format: "label CONTAINS[c] 'free storage'")).firstMatch.exists)
        XCTAssertFalse(alert.staticTexts.allElementsBoundByIndex.map(\.label).joined().contains("credential-canary"))
        alert.buttons["OK"].tap()
        event("event=failed request=1 stage=archive", app: app)
        request(app)
        XCTAssertTrue(alert.waitForExistence(timeout: 10))
        event("event=requested request=2", app: app)
    }

    func testLiteralD6ButtonLosesPresentationWhenItsOriginIsDestroyed() throws {
        let app = launch(["--baseline-d6", "--active-game", "--drop-origin"])
        request(app, controls: true, baseline: true)
        event("event=factory-created", app: app)
        // This is a captured D6 production control, with only its archive
        // producer supplied by the owned fixture. Its button-owned sheet is
        // gone; the corrected tests above require a real native share view.
        XCTAssertFalse(saveToFiles(app).waitForExistence(timeout: 3))
        XCTAssertTrue(app.buttons["library-menu"].exists)
    }
}
