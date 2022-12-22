#include "agent.h"
 
/// 
uint8_t	filename[] = "..\\YaraHunter\\xor.yar";
///

// Proc scanner with callback!

void proc_scanner(void (*callback)(HANDLE, t_udata*, void*), void* udata1) {
	t_udata			udata;
	uint8_t			*time;
	int				bwritten;
	HANDLE			snapshot;
	HANDLE			phndl;
	PROCESSENTRY32	proc_entry;

	bwritten = 0;
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	proc_entry.dwSize = sizeof(PROCESSENTRY32);
	Process32First(snapshot, &proc_entry);
	do {
		phndl = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, proc_entry.th32ProcessID);
		if (!phndl) {
			phndl = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc_entry.th32ProcessID);
		}
		if (phndl) {
			udata.pid = proc_entry.th32ProcessID;
			udata.procname = wide_to_str(proc_entry.szExeFile);
			time = get_time();
			printf("[i]%s::Info: Processing proc: [%s] - %u\n",time, udata.procname, udata.pid);
			callback(phndl, &udata, udata1);
			CloseHandle(phndl);
		}
	} while (Process32Next(snapshot, &proc_entry));
	CloseHandle(snapshot);
}



int agent_callback(YR_SCAN_CONTEXT *context, int message, void *message_data, void *user_data) {
	YR_RULE			*rule;
	YR_STRING		*str;
	t_udata			*udata;
	uint8_t			*time;

	if (message == CALLBACK_MSG_RULE_MATCHING) {
		rule = (YR_RULE*)message_data;
		udata = (t_udata*)user_data;
		yr_rule_strings_foreach(rule, str) {
			time = get_time();
			printf("[*]%s::% 4s: Process:[%s] Pid:[%lu] @ Offet: 0x%p Rule: [%s]\n", time, "Hit", udata->procname, udata->pid, udata->base, str->identifier);
			free(time);
		}
	}
	return CALLBACK_CONTINUE;
}


void scan_region(HANDLE hProc, t_region_info *region, t_yara *yara_engine, t_udata *udata) {
	uint8_t			*buffer;
	size_t			b_read;

	b_read = 0;
	buffer = s_malloc(sizeof(uint8_t) * (region->size + 1));
	buffer[region->size] = 0;
	udata->base = region->base;
	if (ReadProcessMemory(hProc, region->base, buffer, region->size, &b_read) 
		&& b_read > 0) {
		if (b_read > HUNDREDMB) {
			printf("[·]\tWarning: The region is too big: %lu \n", b_read);
			return;
		}
		else {
			yr_rules_scan_mem(yara_engine->rules, buffer, region->size, SCAN_FLAGS_PROCESS_MEMORY, agent_callback, udata, 0);
		}
	}
	free(buffer);
}

void cb_proc_scan(HANDLE hProc, t_udata *udata, void *yara_engine) {
	t_region_info* region;
	t_list			*regs;
	t_list			*aux;
	
	regs = get_process_regions(hProc);
	if (!regs)
		return;
	aux = regs;
	while (aux->next != NULL) {
		region = (t_region_info*)aux->content;
		if (region->protect == PAGE_NOACCESS) {
			aux = aux->next;
			continue;
		}
		scan_region(hProc, region, yara_engine, udata);
		aux = aux->next;
	}
	lst_free(regs);
}

void	deploy_agent() {
	t_yara			yara_engine;

	///

	///
	
	init_yara_engine(&yara_engine, filename);
	proc_scanner(cb_proc_scan, (void*)&yara_engine);
	yr_finish();
}