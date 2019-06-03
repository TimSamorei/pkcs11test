#include <conio.h>
#include <stdio.h>
#include "pcsc.h"
#include "util.h"
#include "clessCardType.h"

int main(int argc, char* argv[])
{
    // Get Data: CLA = 0xFF, INS = 0xCA, P1 = 0x00, P2 = 0x00, Le = 0x00
    BYTE baCmdApduGetData[] = { 0xFF, 0xCA, 0x00, 0x00, 0x00};

    BYTE baResponseApdu[300];
    DWORD lResponseApduLen = 0;

    BYTE atr[40];
    INT     atrLength;
    LONG lRetValue;

    system("cls");
    printf("PCSC API Example - Read Card Serial Number (UID)...\n\n");

    lRetValue = PCSC_Connect(NULL );
    PCSC_EXIT_ON_ERROR(lRetValue);

    lRetValue = PCSC_WaitForCardPresent();
    PCSC_EXIT_ON_ERROR(lRetValue);

    lRetValue = PCSC_ActivateCard();
    PCSC_EXIT_ON_ERROR(lRetValue);

    lRetValue = PCSC_GetAtrString(atr, &atrLength);
    PCSC_EXIT_ON_ERROR(lRetValue);

    // Send pseudo APDU to retrieve the card serical number (UID)
    PCSC_Exchange(baCmdApduGetData,(DWORD)sizeof(baCmdApduGetData),
                  baResponseApdu, &lResponseApduLen);
    PCSC_EXIT_ON_ERROR(lRetValue);

    // Verify if status word SW1SW2 is equal 0x9000.
    if( baResponseApdu[lResponseApduLen - 2] == 0x90 &&
        baResponseApdu[lResponseApduLen - 1] == 0x00)
    {
        // Contactless card detected.
        // Retrieve the card serical number (UID) form the response APDU.
        printHexString("Card Serial Number (UID): 0x",
                             baResponseApdu, lResponseApduLen - 2);

        if( getClessCardType(atr) == Mifare1K)
        {
            printf("Card Type: MIFARE Classic 1k");
        }
        else if( getClessCardType(atr) == Mifare4K)
        {
            printf("Card Type: MIFARE Classic 4k");
        }
        else if( getClessCardType(atr) == MifareUL)
        {
            printf("Card Type: MIFARE Ultralight");
        }
    }

    //lRetValue = PCSC_WaitForCardRemoval();

    PCSC_Disconnect();

    printf("\n");
    getchar();
    return 0;
}
