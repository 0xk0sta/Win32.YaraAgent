#include "list.h"

void lst_free(t_list *lst) {
	t_list *aux;
	while (lst) {
		aux = lst->next;
		free(lst->content);
		free(lst);
		if (!aux)
			break;
		lst = aux;
	}
}

t_list	*lstlast(t_list *lst)
{
	if (!lst)
		return (NULL);
	while (lst->next != NULL)
		lst = lst->next;
	return (lst);
}

void	lstadd_back(t_list **lst, t_list *new)
{
	if (!lst || !new)
		return;
	if (*lst)
		lstlast(*lst)->next = new;
	else
		*lst = new;
}

t_list	*lstnew(void *content)
{
	t_list	*lst;

	lst = malloc(sizeof(t_list));
	if (!lst)
		return (NULL);
	lst->content = content;
	lst->next = NULL;
	return (lst);
}