#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTextEdit>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <iostream>

class FirewallManager;

class TextEditStream : public std::basic_streambuf<char> {
private:
    QTextEdit* textEdit;
public:
    TextEditStream(QTextEdit* te) : textEdit(te) {}
protected:
    virtual std::streamsize xsputn(const char *s, std::streamsize n) {
        textEdit->append(QString::fromUtf8(s, static_cast<int>(n)));
        return n;
    }
    virtual int overflow(int c) {
        if (c != EOF) {
            textEdit->append(QString(static_cast<char>(c)));
        }
        return c;
    }
};

class GUIMainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit GUIMainWindow(FirewallManager* mgr, QWidget *parent = nullptr);
    virtual ~GUIMainWindow();

private:
    FirewallManager* manager;
    QTextEdit* statusText;
    TextEditStream* coutStream;
    std::streambuf* oldCoutBuf;

    QWidget* createBlockTab();
    QWidget* createFirewallTab();
    QWidget* createNetworkTab();
    QWidget* createThreatTab();
    QWidget* createVpnTab();
    QWidget* createLoggingTab();
    QWidget* createStatusTab();
};

#endif // MAINWINDOW_H