#define _CRTDBG_MAP_ALLOC

#include "YaraHunter.h"

int main()
{
	//uint8_t			filename[255];
	
	/*
	printf("Input rule file: ");
	fgets(filename, 254, stdin);
	filename[strlen(filename)-1] = 0;
	*/
	deploy_agent();
	if (!NULL) {
		/* Check leaks! */
		_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
		_CrtDumpMemoryLeaks();
	}
	/* Just wait a bit! */
	system("pause");
}
