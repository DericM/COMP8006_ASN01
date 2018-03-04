#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "helpers.h"
#include "firewall.h"



MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    activated = false;
    refreshLog();
}

MainWindow::~MainWindow()
{
    delete ui;
}



void MainWindow::on_activate_clicked()
{
    if(!activated){
        activated = true;
        ui->activate->setEnabled(false);
        ui->deactivate->setEnabled(true);
        Firewall::clearAllNetFilterRules();
        Firewall::setNetFilterRules();
    }
    refreshLog();
}


void MainWindow::on_deactivate_clicked()
{
    if(activated){
        activated = false;
        ui->activate->setEnabled(true);
        ui->deactivate->setEnabled(false);
        Firewall::clearAllNetFilterRules();
    }
    refreshLog();
}





void MainWindow::refreshLog(){
    std::string result = Firewall::getActiveRules();
    ui->log->setText(QString::fromStdString(result));
}


