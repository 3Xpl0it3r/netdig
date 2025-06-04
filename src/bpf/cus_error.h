#ifndef __CUSTOM_ERROR_H_
#define __CUSTOM_ERROR_H_
enum nat_l3_error {
  L3_ERR_OK,
  L3_ERR_FAILED,
  L3_ERR_NF_ACCEPT, // packet allowed to passed
  L3_ERR_NF_DROP,   // nf_hook_slow retrun -EPERM  (-1)
  L3_ERR_NF_OTH,    // unknown, packet not allowed to passed
                    //
};
#endif // __CUSTOM_ERROR_H_
