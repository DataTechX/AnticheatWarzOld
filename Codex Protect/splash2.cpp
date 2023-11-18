// Video tutorial: http://www.youtube.com/user/vertexbrasil
#include "stdafx.h"
#include "Splash.h"

void SplashShow(){
    CSplash splash1(TEXT("SiwaGuard.bmp"), RGB(128, 128, 128)); //".\\Protect.bmp"
    splash1.ShowSplash();
    Sleep(3000);
    splash1.CloseSplash();
}


