#ifndef KUE_API_H

#define KUE_ALIGNMENT		sizeof(void *)
#define KUE_WORDALIGN(x)	(((x)+(KUE_ALIGNMENT-1))&~(KUE_ALIGNMENT-1))
#define KUE_HLEN		KUE_WORDALIGN(sizeof (struct kue_message))

struct kue_message
{
  unsigned long km_len;        /* length of message */
};

#endif /* KUE_API_H */
