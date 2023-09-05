#include <linux/pci.h>
#include <linux/slab.h>
#include <sound/core.h>
#include <sound/initval.h>


/*Take note of /proc/asound/cards !!
 also, in the learning process,
 can see the pci functions to maybe hook later for easier implementation
 or just open and read/write from sound card*/
/* SNDRV_CARDS: maximum number of cards supported by this module */
static int index[SNDRV_CARDS] = SNDRV_DEFAULT_IDX;
static char *id[SNDRV_CARDS] = SNDRV_DEFAULT_STR;
static bool enable[SNDRV_CARDS] = SNDRV_DEFAULT_ENABLE_PNP;

/* definition of the chip-specific record */
struct chip_t {
        struct snd_card *card;
        /* the rest of the implementation will be in section
         * "PCI Resource Management"
         */
};

/* chip-specific destructor
 * (see "PCI Resource Management")
 */
static int snd_chip_t_free(struct chip_t *chip)
{
        .... /* will be implemented later... */
}

/* component-destructor
 * (see "Management of Cards and Components")
 */
static int snd_chip_t_dev_free(struct snd_device *device)
{
        return snd_chip_t_free(device->device_data);
}

/* chip-specific constructor
 * (see "Management of Cards and Components")
 */
static int snd_chip_t_create(struct snd_card *card,
                             struct pci_dev *pci,
                             struct chip_t **rchip)
{
        struct chip_t *chip;
        int err;
        static struct snd_device_ops ops = {
               .dev_free = snd_chip_t_dev_free,
        };

        *rchip = NULL;

        /* check PCI availability here
         * (see "PCI Resource Management")
         */
        ....

        /* allocate a chip-specific data with zero filled */
        chip = kzalloc(sizeof(*chip), GFP_KERNEL);
        if (chip == NULL)
                return -ENOMEM;

        chip->card = card;

        /* rest of initialization here; will be implemented
         * later, see "PCI Resource Management"
         */
        ....

        err = snd_device_new(card, SNDRV_DEV_LOWLEVEL, chip, &ops);
        if (err < 0) {
                snd_chip_t_free(chip);
                return err;
        }

        *rchip = chip;
        return 0;
}

/* constructor -- see "Driver Constructor" sub-section */
static int snd_chip_t_probe(struct pci_dev *pci,
                            const struct pci_device_id *pci_id)
{
        static int dev;
        struct snd_card *card;
        struct chip_t *chip;
        int err;

        /* (1) */
        if (dev >= SNDRV_CARDS)
                return -ENODEV;
        if (!enable[dev]) {
                dev++;
                return -ENOENT;
        }

        /* (2) */
        err = snd_card_new(&pci->dev, index[dev], id[dev], THIS_MODULE,
                           0, &card);
        if (err < 0)
                return err;

        /* (3) */
        err = snd_chip_t_create(card, pci, &chip);
        if (err < 0) {
                snd_card_free(card);
                return err;
        }

        /* (4) */
        strcpy(card->driver, "My Chip");
        strcpy(card->shortname, "My Own Chip 123");
        sprintf(card->longname, "%s at 0x%lx irq %i",
                card->shortname, chip->ioport, chip->irq);

        /* (5) */
        .... /* implemented later */

        /* (6) */
        err = snd_card_register(card);
        if (err < 0) {
                snd_card_free(card);
                return err;
        }

        /* (7) */
        pci_set_drvdata(pci, card);
        dev++;
        return 0;
}

/* !! destructor -- see the "Destructor" sub-section ***can "destruct" another pci driver*** !!!*/
static void snd_chip_t_remove(struct pci_dev *pci)
{
        snd_card_free(pci_get_drvdata(pci));
        pci_set_drvdata(pci, NULL);
}