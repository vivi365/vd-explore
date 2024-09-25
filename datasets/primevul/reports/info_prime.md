# PrimeVul Dataset Analysis

## Dataset Overview
```
DatasetDict({
    train: Dataset({
        features: ['project', 'commit_id', 'target', 'func', 'cwe', 'big_vul_idx', 'idx', 'hash', 'size', 'message', 'dataset'],
        num_rows: 184427
    })
    test: Dataset({
        features: ['project', 'commit_id', 'target', 'func', 'cwe', 'big_vul_idx', 'idx', 'hash', 'size', 'message', 'dataset'],
        num_rows: 25911
    })
    valid: Dataset({
        features: ['project', 'commit_id', 'target', 'func', 'cwe', 'big_vul_idx', 'idx', 'hash', 'size', 'message', 'dataset'],
        num_rows: 25430
    })
})
```

## First Sample
```json
{
  "project": "openssl",
  "commit_id": "ca989269a2876bae79393bd54c3e72d49975fc75",
  "target": 1,
  "func": " long ssl_get_algorithm2(SSL *s)\n        {\n        long alg2 = s->s3->tmp.new_cipher->algorithm2;\n  ... (truncated)",
  "cwe": "CWE-310",
  "hash": "255087747659226932756944884868284698117",
  "size": null,
  "message": null,
  "dataset": null
}
```

## Dataset Info:
### train:
```
Dataset({
    features: ['project', 'commit_id', 'target', 'func', 'cwe', 'big_vul_idx', 'idx', 'hash', 'size', 'message', 'dataset'],
    num_rows: 184427
})
```
### test:
```
Dataset({
    features: ['project', 'commit_id', 'target', 'func', 'cwe', 'big_vul_idx', 'idx', 'hash', 'size', 'message', 'dataset'],
    num_rows: 25911
})
```
### valid:
```
Dataset({
    features: ['project', 'commit_id', 'target', 'func', 'cwe', 'big_vul_idx', 'idx', 'hash', 'size', 'message', 'dataset'],
    num_rows: 25430
})
```

## Column Names:
```
['project', 'commit_id', 'target', 'func', 'cwe', 'big_vul_idx', 'idx', 'hash', 'size', 'message', 'dataset']
```

## Sample Sizes:
- **train**: 184427 samples
- **test**: 25911 samples
- **valid**: 25430 samples

## Random Sample Entries:

### Random Sample 1 from test:
```json
{
  "project": "Onigmo",
  "commit_id": "ce13b17b955e0b6dfc6606b1fdbd4755590b360b",
  "target": 0,
  "func": "big5_is_mbc_ambiguous(OnigCaseFoldType flag,\n\t\t      const UChar** pp, const UChar* end, OnigEncodin... (truncated)",
  "cwe": "nan",
  "hash": "138261098641466502744963187058717353071",
  "size": 5.0,
  "message": "merge Ruby 1.9.2",
  "dataset": "other"
}
```

### Random Sample 2 from test:
```json
{
  "project": "vim",
  "commit_id": "d6c67629ed05aae436164eec474832daf8ba7420",
  "target": 0,
  "func": "make_get_auname(cmdidx_T cmdidx)\n{\n    switch (cmdidx)\n    {\n\tcase CMD_make:\t    return (char_u *)\"m... (truncated)",
  "cwe": "nan",
  "hash": "246102649915136104840892354697243823211",
  "size": 13.0,
  "message": "patch 9.0.0260: using freed memory when using 'quickfixtextfunc' recursively\n\nProblem:    Using free... (truncated)",
  "dataset": "other"
}
```

### Random Sample 3 from test:
```json
{
  "project": "MilkyTracker",
  "commit_id": "7afd55c42ad80d01a339197a2d8b5461d214edaf",
  "target": 0,
  "func": "mp_sint32 PlayerGeneric::setBufferSize(mp_uint32 bufferSize)\n{\n\tmp_sint32 res = 0;\n\t\n\tthis->bufferSi... (truncated)",
  "cwe": "nan",
  "hash": "128842771335903851486886614712202107218",
  "size": 27.0,
  "message": "Fix use-after-free in PlayerGeneric destructor",
  "dataset": "other"
}
```

## Basic Statistics (if applicable):

### target:
#### Train:
- Mean: 0.03
- Min: 0
- Max: 1
#### Test:
- Mean: 0.03
- Min: 0
- Max: 1
#### Valid:
- Mean: 0.03
- Min: 0
- Max: 1

### size:
#### Train:
- Mean: 45.77
- Min: 1.0
- Max: 24047.0
#### Test:
- Mean: 43.44
- Min: 1.0
- Max: 3978.0
#### Valid:
- Mean: 40.36
- Min: 1.0
- Max: 2914.0

## Unique Values for Categorical Columns (if applicable):

### project: 755 unique values

### commit_id: 6827 unique values

### func: 235768 unique values

### cwe: 140 unique values

### hash: 235768 unique values

### message: 4247 unique values

### dataset:
```
{'other', None}
```

## Unique CWEs:
Number of unique CWEs: 138

### All unique CWEs:
```
CWE-1021
CWE-119
CWE-120
CWE-125
CWE-129
CWE-134
CWE-16
CWE-17
CWE-172
CWE-189
CWE-19
CWE-190
CWE-191
CWE-20
CWE-200
CWE-209
CWE-22
CWE-252
CWE-254
CWE-255
CWE-264
CWE-269
CWE-276
CWE-284
CWE-285
CWE-287
CWE-290
CWE-295
CWE-310
CWE-311
CWE-320
CWE-327
CWE-331
CWE-345
CWE-347
CWE-352
CWE-354
CWE-361
CWE-362
CWE-369
CWE-388
CWE-399
CWE-400
CWE-401
CWE-404
CWE-415
CWE-416
CWE-426
CWE-476
CWE-502
CWE-532
CWE-59
CWE-601
CWE-611
CWE-613
CWE-617
CWE-664
CWE-665
CWE-668
CWE-674
CWE-681
CWE-682
CWE-693
CWE-704
CWE-732
CWE-74
CWE-754
CWE-755
CWE-77
CWE-770
CWE-772
CWE-78
CWE-787
CWE-79
CWE-824
CWE-834
CWE-835
CWE-862
CWE-89
CWE-908
CWE-909
CWE-918
CWE-94
NVD-CWE-Other
NVD-CWE-noinfo
['CWE-119', 'CWE-787']
['CWE-119']
['CWE-120']
['CWE-121']
['CWE-125']
['CWE-134']
['CWE-17']
['CWE-189']
['CWE-19']
['CWE-190']
['CWE-193']
['CWE-20', 'CWE-119']
['CWE-20']
['CWE-200']
['CWE-203']
['CWE-22']
['CWE-254']
['CWE-264']
['CWE-269']
['CWE-284']
['CWE-287']
['CWE-295']
['CWE-310']
['CWE-326']
['CWE-327']
['CWE-362']
['CWE-369']
['CWE-399']
['CWE-400']
['CWE-404', 'CWE-703']
['CWE-404']
['CWE-415']
['CWE-416']
['CWE-444']
['CWE-476']
['CWE-59']
['CWE-601']
['CWE-617']
['CWE-703', 'CWE-295']
['CWE-703', 'CWE-667']
['CWE-755']
['CWE-770']
['CWE-772']
['CWE-78']
['CWE-787']
['CWE-79']
['CWE-835']
['CWE-89']
['CWE-908']
['CWE-909']
['CWE-93']
['CWE-94']
[]
```

## Sample with target: 1
### Vulnerable sample from train:
```json
{
  "project": "ImageMagick",
  "commit_id": "8f8959033e4e59418d6506b345829af1f7a71127",
  "target": 1,
  "func": "static Image *ReadSGIImage(const ImageInfo *image_info,ExceptionInfo *exception)\n{\n  Image\n    *imag... (truncated)",
  "cwe": "CWE-125",
  "hash": "9093028214754755496430325610921655674",
  "size": null,
  "message": null,
  "dataset": null
}
```
