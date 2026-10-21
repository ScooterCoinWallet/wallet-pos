// Copyright (c) 2018-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/apptests.h>

#include <chainparams.h>
#include <key.h>
#include <qt/bitcoin.h>
#include <qt/bitcoingui.h>
#include <qt/networkstyle.h>
#include <qt/rpcconsole.h>
#include <shutdown.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <validation.h>

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <QAction>
#include <QDesktopServices>
#include <QEventLoop>
#include <QLineEdit>
#include <QScopedPointer>
#include <QTest>
#include <QTextEdit>
#include <QtGlobal>
#include <QtTest/QtTestWidgets>
#include <QtTest/QtTestGui>

namespace {
//! Call getblockchaininfo RPC and check first field of JSON output.
void TestRpcCommand(RPCConsole* console)
{
    QEventLoop loop;
    QTextEdit* messagesWidget = console->findChild<QTextEdit*>("messagesWidget");
    QObject::connect(messagesWidget, &QTextEdit::textChanged, &loop, &QEventLoop::quit);
    QLineEdit* lineEdit = console->findChild<QLineEdit*>("lineEdit");
    QTest::keyClicks(lineEdit, "getblockchaininfo");
    QTest::keyClick(lineEdit, Qt::Key_Return);
    loop.exec();
    QString output = messagesWidget->toPlainText();
    UniValue value;
    value.read(output.right(output.size() - output.lastIndexOf(QChar::ObjectReplacementCharacter) - 1).toStdString());
    QCOMPARE(value["chain"].get_str(), std::string("regtest"));
}
} // namespace

//! Entry point for BitcoinApplication tests.
void AppTests::appTests()
{
#ifdef Q_OS_MAC
    if (QApplication::platformName() == "minimal") {
        // Disable for mac on "minimal" platform to avoid crashes inside the Qt
        // framework when it tries to look up unimplemented cocoa functions,
        // and fails to handle returned nulls
        // (https://bugreports.qt.io/browse/QTBUG-49686).
        QWARN("Skipping AppTests on mac build with 'minimal' platform set due to Qt bugs. To run AppTests, invoke "
              "with 'QT_QPA_PLATFORM=cocoa test_bitcoin-qt' on mac, or else use a linux or windows build.");
        return;
    }
#endif

    BasicTestingSetup test{CBaseChainParams::REGTEST}; // Create a temp data directory to backup the gui settings to
    ECC_Stop(); // Already started by the common test setup, so stop it to avoid interference
    LogInstance().DisconnectTestLogger();

    m_app.parameterSetup();
    m_app.createOptionsModel(true /* reset settings */);
    QScopedPointer<const NetworkStyle> style(NetworkStyle::instantiate(Params().NetworkIDString()));
    m_app.setupPlatformStyle();
    m_app.createWindow(style.data());
    connect(&m_app, &BitcoinApplication::windowShown, this, &AppTests::guiTests);
    expectCallback("guiTests");
    m_app.baseInitialize();
    m_app.requestInitialize();
    m_app.exec();
    m_app.requestShutdown();
    m_app.exec();

    // Reset global state to avoid interfering with later tests.
    AbortShutdown();
    UnloadBlockIndex();
}

//! Entry point for BitcoinGUI tests.
void AppTests::guiTests(BitcoinGUI* window)
{
    HandleCallback callback{"guiTests", *this};
    // Intercept browser launches so link tests never contact a website or send wallet data.
    struct UrlHandlerGuard {
        ~UrlHandlerGuard() { QDesktopServices::unsetUrlHandler("https"); }
    } url_handler_guard;
    QDesktopServices::setUrlHandler("https", this, "recordProjectUrl");
    const QList<QPair<QString, QUrl>> links{
        {"projectWebsiteAction", QUrl("https://scootercoin.org/")},
        {"blockExplorerAction", QUrl("https://explorer.scootercoin.org/")},
    };
    for (const auto& link : links) {
        QAction* project_action = window->findChild<QAction*>(link.first);
        QVERIFY(project_action);
        const int previous = m_project_urls.size();
        project_action->trigger();
        QCOMPARE(m_project_urls.size(), previous + 1);
        QCOMPARE(m_project_urls.last(), link.second);
        QVERIFY(!m_project_urls.last().hasQuery());
        QVERIFY(!m_project_urls.last().hasFragment());
    }
    QAction* theme_action = window->findChild<QAction*>("projectThemeAction");
    QVERIFY(theme_action);
    theme_action->setChecked(true);
    QVERIFY(!window->styleSheet().isEmpty());
    theme_action->setChecked(false);
    QVERIFY(window->styleSheet().isEmpty());
    theme_action->setChecked(true);
    QVERIFY(!window->styleSheet().isEmpty());
    connect(window, &BitcoinGUI::consoleShown, this, &AppTests::consoleTests);
    expectCallback("consoleTests");
    QAction* action = window->findChild<QAction*>("openRPCConsoleAction");
    action->activate(QAction::Trigger);
}

void AppTests::recordProjectUrl(const QUrl& url)
{
    m_project_urls.append(url);
}

//! Entry point for RPCConsole tests.
void AppTests::consoleTests(RPCConsole* console)
{
    HandleCallback callback{"consoleTests", *this};
    TestRpcCommand(console);
}

//! Destructor to shut down after the last expected callback completes.
AppTests::HandleCallback::~HandleCallback()
{
    auto& callbacks = m_app_tests.m_callbacks;
    auto it = callbacks.find(m_callback);
    assert(it != callbacks.end());
    callbacks.erase(it);
    if (callbacks.empty()) {
        m_app_tests.m_app.quit();
    }
}
