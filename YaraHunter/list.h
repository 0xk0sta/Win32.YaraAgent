#pragma once
#include <Windows.h>

typedef struct s_list
{
	void			*content;
	struct s_list	*next;
}t_list;

void lst_free(t_list *lst);
t_list	*lstlast(t_list *lst);
void	lstadd_back(t_list **lst, t_list *new);
t_list	*lstnew(void *content);