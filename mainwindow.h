#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_activate_clicked();

    void on_deactivate_clicked();

private:
    bool activated;
    Ui::MainWindow *ui;

    void refreshLog();
};

#endif // MAINWINDOW_H
