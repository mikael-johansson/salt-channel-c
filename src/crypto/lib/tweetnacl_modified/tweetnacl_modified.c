#include "tweetnacl_modified.h"
#include <stddef.h>
#include <string.h>

#define FOR(i,n) for (i = 0;i < n;++i)
#define sv static void


typedef unsigned char u8;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef long long i64;
typedef i64 gf[16];
extern void randombytes(u8 *,u64);

/* From libsodium */

#define ROTR64(X, B) rotr64((X), (B))
static inline uint64_t
rotr64(const uint64_t x, const int b)
{
    return (x >> b) | (x << (64 - b));
}
/* ----- */

#define LOAD64_BE(SRC) load64_be(SRC)
static inline uint64_t
load64_be(const uint8_t src[8])
{
#ifdef NATIVE_BIG_ENDIAN
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint64_t w = (uint64_t) src[7];
    w |= (uint64_t) src[6] <<  8;
    w |= (uint64_t) src[5] << 16;
    w |= (uint64_t) src[4] << 24;
    w |= (uint64_t) src[3] << 32;
    w |= (uint64_t) src[2] << 40;
    w |= (uint64_t) src[1] << 48;
    w |= (uint64_t) src[0] << 56;
    return w;
#endif
}

#define STORE64_BE(DST, W) store64_be((DST), (W))
static inline void
store64_be(uint8_t dst[8], uint64_t w)
{
#ifdef NATIVE_BIG_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[7] = (uint8_t) w; w >>= 8;
    dst[6] = (uint8_t) w; w >>= 8;
    dst[5] = (uint8_t) w; w >>= 8;
    dst[4] = (uint8_t) w; w >>= 8;
    dst[3] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[0] = (uint8_t) w;
#endif
}

static const u8
  _0[16],
  _9[32] = {9};
static const gf
  gf0,
  gf1 = {1},
  _121665 = {0xDB41,1},
  D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203},
  D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406},
  X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169},
  Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666},
  I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

static u32 L32(u32 x,int c) { return (x << c) | ((x&0xffffffff) >> (32 - c)); }

static u32 ld32(const u8 *x)
{
  u32 u = x[3];
  u = (u<<8)|x[2];
  u = (u<<8)|x[1];
  return (u<<8)|x[0];
}

sv st32(u8 *x,u32 u)
{
  int i;
  FOR(i,4) { x[i] = u; u >>= 8; }
}

static int vn(const u8 *x,const u8 *y,u32 n)
{
  u32 i,d = 0;
  FOR(i,n) d |= x[i]^y[i];
  return (1 & ((d - 1) >> 8)) - 1;
}

int crypto_verify_16(const u8 *x,const u8 *y)
{
  return vn(x,y,16);
}

int crypto_verify_32(const u8 *x,const u8 *y)
{
  return vn(x,y,32);
}

int crypto_verify_64(const u8 *x,const u8 *y)
{
  return vn(x,y,64);
}

sv core(u8 *out,const u8 *in,const u8 *k,const u8 *c,int h)
{
  u32 w[16],x[16],y[16],t[4];
  int i,j,m;

  FOR(i,4) {
    x[5*i] = ld32(c+4*i);
    x[1+i] = ld32(k+4*i);
    x[6+i] = ld32(in+4*i);
    x[11+i] = ld32(k+16+4*i);
  }

  FOR(i,16) y[i] = x[i];

  FOR(i,20) {
    FOR(j,4) {
      FOR(m,4) t[m] = x[(5*j+4*m)%16];
      t[1] ^= L32(t[0]+t[3], 7);
      t[2] ^= L32(t[1]+t[0], 9);
      t[3] ^= L32(t[2]+t[1],13);
      t[0] ^= L32(t[3]+t[2],18);
      FOR(m,4) w[4*j+(j+m)%4] = t[m];
    }
    FOR(m,16) x[m] = w[m];
  }

  if (h) {
    FOR(i,16) x[i] += y[i];
    FOR(i,4) {
      x[5*i] -= ld32(c+4*i);
      x[6+i] -= ld32(in+4*i);
    }
    FOR(i,4) {
      st32(out+4*i,x[5*i]);
      st32(out+16+4*i,x[6+i]);
    }
  } else
    FOR(i,16) st32(out + 4 * i,x[i] + y[i]);
}

int crypto_core_salsa20(u8 *out,const u8 *in,const u8 *k,const u8 *c)
{
  core(out,in,k,c,0);
  return 0;
}

int crypto_core_hsalsa20(u8 *out,const u8 *in,const u8 *k,const u8 *c)
{
  core(out,in,k,c,1);
  return 0;
}

static const u8 sigma[16] = "expand 32-byte k";

int crypto_stream_salsa20_xor(u8 *c,const u8 *m,u64 b,const u8 *n,const u8 *k)
{
  u8 z[16],x[64];
  u32 u,i;
  if (!b) return 0;
  FOR(i,16) z[i] = 0;
  FOR(i,8) z[i] = n[i];
  while (b >= 64) {
    crypto_core_salsa20(x,z,k,sigma);
    FOR(i,64) c[i] = (m?m[i]:0) ^ x[i];
    u = 1;
    for (i = 8;i < 16;++i) {
      u += (u32) z[i];
      z[i] = u;
      u >>= 8;
    }
    b -= 64;
    c += 64;
    if (m) m += 64;
  }
  if (b) {
    crypto_core_salsa20(x,z,k,sigma);
    FOR(i,b) c[i] = (m?m[i]:0) ^ x[i];
  }
  return 0;
}

int crypto_stream_salsa20(u8 *c,u64 d,const u8 *n,const u8 *k)
{
  return crypto_stream_salsa20_xor(c,0,d,n,k);
}

int crypto_stream(u8 *c,u64 d,const u8 *n,const u8 *k)
{
  u8 s[32];
  crypto_core_hsalsa20(s,n,k,sigma);
  return crypto_stream_salsa20(c,d,n+16,s);
}

int crypto_stream_xor(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *k)
{
  u8 s[32];
  crypto_core_hsalsa20(s,n,k,sigma);
  return crypto_stream_salsa20_xor(c,m,d,n+16,s);
}

sv add1305(u32 *h,const u32 *c)
{
  u32 j,u = 0;
  FOR(j,17) {
    u += h[j] + c[j];
    h[j] = u & 255;
    u >>= 8;
  }
}

static const u32 minusp[17] = {
  5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
} ;

int crypto_onetimeauth(u8 *out,const u8 *m,u64 n,const u8 *k)
{
  u32 s,i,j,u,x[17],r[17],h[17],c[17],g[17];

  FOR(j,17) r[j]=h[j]=0;
  FOR(j,16) r[j]=k[j];
  r[3]&=15;
  r[4]&=252;
  r[7]&=15;
  r[8]&=252;
  r[11]&=15;
  r[12]&=252;
  r[15]&=15;

  while (n > 0) {
    FOR(j,17) c[j] = 0;
    for (j = 0;(j < 16) && (j < n);++j) c[j] = m[j];
    c[j] = 1;
    m += j; n -= j;
    add1305(h,c);
    FOR(i,17) {
      x[i] = 0;
      FOR(j,17) x[i] += h[j] * ((j <= i) ? r[i - j] : 320 * r[i + 17 - j]);
    }
    FOR(i,17) h[i] = x[i];
    u = 0;
    FOR(j,16) {
      u += h[j];
      h[j] = u & 255;
      u >>= 8;
    }
    u += h[16]; h[16] = u & 3;
    u = 5 * (u >> 2);
    FOR(j,16) {
      u += h[j];
      h[j] = u & 255;
      u >>= 8;
    }
    u += h[16]; h[16] = u;
  }

  FOR(j,17) g[j] = h[j];
  add1305(h,minusp);
  s = -(h[16] >> 7);
  FOR(j,17) h[j] ^= s & (g[j] ^ h[j]);

  FOR(j,16) c[j] = k[j + 16];
  c[16] = 0;
  add1305(h,c);
  FOR(j,16) out[j] = h[j];
  return 0;
}

int crypto_onetimeauth_verify(const u8 *h,const u8 *m,u64 n,const u8 *k)
{
  u8 x[16];
  crypto_onetimeauth(x,m,n,k);
  return crypto_verify_16(h,x);
}

int crypto_secretbox(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *k)
{
  int i;
  if (d < 32) return -1;
  crypto_stream_xor(c,m,d,n,k);
  crypto_onetimeauth(c + 16,c + 32,d - 32,c);
  FOR(i,16) c[i] = 0;
  return 0;
}

int crypto_secretbox_open(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *k)
{
  int i;
  u8 x[32];
  if (d < 32) return -1;
  crypto_stream(x,32,n,k);
  if (crypto_onetimeauth_verify(c + 16,c + 32,d - 32,x) != 0) return -1;
  crypto_stream_xor(m,c,d,n,k);
  FOR(i,32) m[i] = 0;
  return 0;
}

sv set25519(gf r, const gf a)
{
  int i;
  FOR(i,16) r[i]=a[i];
}

sv car25519(gf o)
{
  int i;
  i64 c;
  FOR(i,16) {
    o[i]+=(1LL<<16);
    c=o[i]>>16;
    o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
    o[i]-=c<<16;
  }
}

sv sel25519(gf p,gf q,int b)
{
  i64 t,i,c=~(b-1);
  FOR(i,16) {
    t= c&(p[i]^q[i]);
    p[i]^=t;
    q[i]^=t;
  }
}

sv pack25519(u8 *o,const gf n)
{
  int i,j,b;
  gf m,t;
  FOR(i,16) t[i]=n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  FOR(j,2) {
    m[0]=t[0]-0xffed;
    for(i=1;i<15;i++) {
      m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
      m[i-1]&=0xffff;
    }
    m[15]=t[15]-0x7fff-((m[14]>>16)&1);
    b=(m[15]>>16)&1;
    m[14]&=0xffff;
    sel25519(t,m,1-b);
  }
  FOR(i,16) {
    o[2*i]=t[i]&0xff;
    o[2*i+1]=t[i]>>8;
  }
}

static int neq25519(const gf a, const gf b)
{
  u8 c[32],d[32];
  pack25519(c,a);
  pack25519(d,b);
  return crypto_verify_32(c,d);
}

static u8 par25519(const gf a)
{
  u8 d[32];
  pack25519(d,a);
  return d[0]&1;
}

sv unpack25519(gf o, const u8 *n)
{
  int i;
  FOR(i,16) o[i]=n[2*i]+((i64)n[2*i+1]<<8);
  o[15]&=0x7fff;
}

sv A(gf o,const gf a,const gf b)
{
  int i;
  FOR(i,16) o[i]=a[i]+b[i];
}

sv Z(gf o,const gf a,const gf b)
{
  int i;
  FOR(i,16) o[i]=a[i]-b[i];
}

sv M(gf o,const gf a,const gf b)
{
  i64 i,j,t[31];
  FOR(i,31) t[i]=0;
  FOR(i,16) FOR(j,16) t[i+j]+=a[i]*b[j];
  FOR(i,15) t[i]+=38*t[i+16];
  FOR(i,16) o[i]=t[i];
  car25519(o);
  car25519(o);
}

sv S(gf o,const gf a)
{
  M(o,a,a);
}

sv inv25519(gf o,const gf i)
{
  gf c;
  int a;
  FOR(a,16) c[a]=i[a];
  for(a=253;a>=0;a--) {
    S(c,c);
    if(a!=2&&a!=4) M(c,c,i);
  }
  FOR(a,16) o[a]=c[a];
}

sv pow2523(gf o,const gf i)
{
  gf c;
  int a;
  FOR(a,16) c[a]=i[a];
  for(a=250;a>=0;a--) {
    S(c,c);
    if(a!=1) M(c,c,i);
  }
  FOR(a,16) o[a]=c[a];
}

int crypto_scalarmult(u8 *q,const u8 *n,const u8 *p)
{
  u8 z[32];
  i64 x[80],r,i;
  gf a,b,c,d,e,f;
  FOR(i,31) z[i]=n[i];
  z[31]=(n[31]&127)|64;
  z[0]&=248;
  unpack25519(x,p);
  FOR(i,16) {
    b[i]=x[i];
    d[i]=a[i]=c[i]=0;
  }
  a[0]=d[0]=1;
  for(i=254;i>=0;--i) {
    r=(z[i>>3]>>(i&7))&1;
    sel25519(a,b,r);
    sel25519(c,d,r);
    A(e,a,c);
    Z(a,a,c);
    A(c,b,d);
    Z(b,b,d);
    S(d,e);
    S(f,a);
    M(a,c,a);
    M(c,b,e);
    A(e,a,c);
    Z(a,a,c);
    S(b,a);
    Z(c,d,f);
    M(a,c,_121665);
    A(a,a,d);
    M(c,c,a);
    M(a,d,f);
    M(d,b,x);
    S(b,e);
    sel25519(a,b,r);
    sel25519(c,d,r);
  }
  FOR(i,16) {
    x[i+16]=a[i];
    x[i+32]=c[i];
    x[i+48]=b[i];
    x[i+64]=d[i];
  }
  inv25519(x+32,x+32);
  M(x+16,x+16,x+32);
  pack25519(q,x+16);
  return 0;
}

int crypto_scalarmult_base(u8 *q,const u8 *n)
{ 
  return crypto_scalarmult(q,n,_9);
}

int crypto_box_keypair(u8 *y,u8 *x)
{
  randombytes(x,32);
  return crypto_scalarmult_base(y,x);
}

int crypto_box_beforenm(u8 *k,const u8 *y,const u8 *x)
{
  u8 s[32];
  crypto_scalarmult(s,x,y);
  return crypto_core_hsalsa20(k,_0,s,sigma);
}

int crypto_box_afternm(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *k)
{
  return crypto_secretbox(c,m,d,n,k);
}

int crypto_box_open_afternm(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *k)
{
  return crypto_secretbox_open(m,c,d,n,k);
}

int crypto_box(u8 *c,const u8 *m,u64 d,const u8 *n,const u8 *y,const u8 *x)
{
  u8 k[32];
  crypto_box_beforenm(k,y,x);
  return crypto_box_afternm(c,m,d,n,k);
}

int crypto_box_open(u8 *m,const u8 *c,u64 d,const u8 *n,const u8 *y,const u8 *x)
{
  u8 k[32];
  crypto_box_beforenm(k,y,x);
  return crypto_box_open_afternm(m,c,d,n,k);
}

sv add(gf p[4],gf q[4])
{
  gf a,b,c,d,t,e,f,g,h;
  
  Z(a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(a, a, t);
  A(b, p[0], p[1]);
  A(t, q[0], q[1]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, a);

  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
}

sv cswap(gf p[4],gf q[4],u8 b)
{
  int i;
  FOR(i,4)
    sel25519(p[i],q[i],b);
}

sv pack(u8 *r,gf p[4])
{
  gf tx, ty, zi;
  inv25519(zi, p[2]); 
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx) << 7;
}

sv scalarmult(gf p[4],gf q[4],const u8 *s)
{
  int i;
  set25519(p[0],gf0);
  set25519(p[1],gf1);
  set25519(p[2],gf1);
  set25519(p[3],gf0);
  for (i = 255;i >= 0;--i) {
    u8 b = (s[i/8]>>(i&7))&1;
    cswap(p,q,b);
    add(q,p);
    add(p,p);
    cswap(p,q,b);
  }
}

sv scalarbase(gf p[4],const u8 *s)
{
  gf q[4];
  set25519(q[0],X);
  set25519(q[1],Y);
  set25519(q[2],gf1);
  M(q[3],X,Y);
  scalarmult(p,q,s);
}

int crypto_sign_keypair(u8 *pk, u8 *sk)
{
  u8 d[64];
  gf p[4];
  int i;

  randombytes(sk, 32);
  crypto_hash_sha512_state_tweet hash_state;
  crypto_hash_sha512_init_tweet(&hash_state);
  crypto_hash_sha512_update_tweet(&hash_state, sk, 32);
  crypto_hash_sha512_final_tweet(&hash_state, d);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  scalarbase(p,d);
  pack(pk,p);

  FOR(i,32) sk[32 + i] = pk[i];
  return 0;
}

static const u64 L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

sv modL(u8 *r,i64 x[64])
{
  i64 carry,i,j;
  for (i = 63;i >= 32;--i) {
    carry = 0;
    for (j = i - 32;j < i - 12;++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry << 8;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  FOR(j,32) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  FOR(j,32) x[j] -= carry * L[j];
  FOR(i,32) {
    x[i+1] += x[i] >> 8;
    r[i] = x[i] & 255;
  }
}

sv reduce(u8 *r)
{
  i64 x[64],i;
  FOR(i,64) x[i] = (u64) r[i];
  FOR(i,64) r[i] = 0;
  modL(r,x);
}

int crypto_sign(u8 *sm,u64 *smlen,const u8 *m,u64 n,const u8 *sk)
{
  u8 d[64],h[64],r[64];
  i64 j,x[64];
  u64 i;
  gf p[4];
  crypto_hash_sha512_state_tweet hash_state;

  crypto_hash_sha512_init_tweet(&hash_state);
  crypto_hash_sha512_update_tweet(&hash_state, sk, 32);
  crypto_hash_sha512_final_tweet(&hash_state, d);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  *smlen = n+64;
  FOR(i,n) sm[64 + i] = m[i];
  FOR(i,32) sm[32 + i] = d[32 + i];

  crypto_hash_sha512_init_tweet(&hash_state);
  crypto_hash_sha512_update_tweet(&hash_state, sm+32, n+32);
  crypto_hash_sha512_final_tweet(&hash_state, r);
  reduce(r);
  scalarbase(p,r);
  pack(sm,p);

  FOR(i,32) sm[i+32] = sk[i+32];
  crypto_hash_sha512_init_tweet(&hash_state);
  crypto_hash_sha512_update_tweet(&hash_state, sm, n + 64);
  crypto_hash_sha512_final_tweet(&hash_state, h);
  reduce(h);

  FOR(i,64) x[i] = 0;
  FOR(i,32) x[i] = (u64) r[i];
  FOR(i,32) FOR(j,32) x[i+j] += h[i] * (u64) d[j];
  modL(sm + 32,x);

  return 0;
}

static int unpackneg(gf r[4],const u8 p[32])
{
  gf t, chk, num, den, den2, den4, den6;
  set25519(r[2],gf1);
  unpack25519(r[1],p);
  S(num,r[1]);
  M(den,num,D);
  Z(num,num,r[2]);
  A(den,r[2],den);

  S(den2,den);
  S(den4,den2);
  M(den6,den4,den2);
  M(t,den6,num);
  M(t,t,den);

  pow2523(t,t);
  M(t,t,num);
  M(t,t,den);
  M(t,t,den);
  M(r[0],t,den);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) M(r[0],r[0],I);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) return -1;

  if (par25519(r[0]) == (p[31]>>7)) Z(r[0],gf0,r[0]);

  M(r[3],r[0],r[1]);
  return 0;
}

int crypto_sign_open(u8 *m,u64 *mlen,const u8 *sm,u64 n,const u8 *pk)
{
  u64 i;
  u8 t[32],h[64];
  gf p[4],q[4];

  *mlen = -1;
  if (n < 64) return -1;

  if (unpackneg(q,pk)) return -1;

  FOR(i,n) m[i] = sm[i];
  FOR(i,32) m[i+32] = pk[i];
  crypto_hash_sha512_state_tweet hash_state;
  crypto_hash_sha512_init_tweet(&hash_state);
  crypto_hash_sha512_update_tweet(&hash_state, m,n);
  crypto_hash_sha512_final_tweet(&hash_state, h);
  reduce(h);
  scalarmult(p,q,h);

  scalarbase(q,sm + 32);
  add(p,q);
  pack(t,p);

  n -= 64;
  if (crypto_verify_32(sm, t)) {
    FOR(i,n) m[i] = 0;
    return -1;
  }

  FOR(i,n) m[i] = sm[i + 64];
  *mlen = n;
  return 0;
}

int crypto_sign_verify_detached_tweet(const unsigned char *sig,
                                const unsigned char *m,
                                unsigned long long mlen,
                                const unsigned char *pk)
{

    crypto_hash_sha512_state_tweet hash_state;
    unsigned long long i;
    u8 t[32],h[64];
    gf p[4],q[4];

    if (unpackneg(q,pk)) return -1;

    crypto_hash_sha512_init_tweet(&hash_state);

    FOR(i,32) h[i] = sig[i];
    FOR(i,32) h[i+32] = pk[i];

    crypto_hash_sha512_update_tweet(&hash_state, h, 64);
    crypto_hash_sha512_update_tweet(&hash_state, m, mlen);
    crypto_hash_sha512_final_tweet(&hash_state, h);

    reduce(h);
    scalarmult(p,q,h);
    scalarbase(q,sig + 32);
    add(p,q);
    pack(t,p);

    if (crypto_verify_32(sig, t)) {
        return -1;
    }

    return 0;
}

static void
be64enc_vect(unsigned char *dst, const uint64_t *src, size_t len)
{
    size_t i;

    for (i = 0; i < len / 8; i++) {
        STORE64_BE(dst + i * 8, src[i]);
    }
}

static void
be64dec_vect(uint64_t *dst, const unsigned char *src, size_t len)
{
    size_t i;

    for (i = 0; i < len / 8; i++) {
        dst[i] = LOAD64_BE(src + i * 8);
    }
}


static const uint64_t Krnd[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#define Ch(x, y, z) ((x & (y ^ z)) ^ z)
#define Maj(x, y, z) ((x & (y | z)) | (y & z))
#define SHR(x, n) (x >> n)
#define ROTR(x, n) ROTR64(x, n)
#define S0(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define S1(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define s0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7))
#define s1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6))

#define RND(a, b, c, d, e, f, g, h, k) \
    h += S1(e) + Ch(e, f, g) + k;      \
    d += h;                            \
    h += S0(a) + Maj(a, b, c);

#define RNDr(S, W, i, ii)                                                   \
    RND(S[(80 - i) % 8], S[(81 - i) % 8], S[(82 - i) % 8], S[(83 - i) % 8], \
        S[(84 - i) % 8], S[(85 - i) % 8], S[(86 - i) % 8], S[(87 - i) % 8], \
        W[i + ii] + Krnd[i + ii])

#define MSCH(W, ii, i) \
    W[i + ii + 16] =   \
        s1(W[i + ii + 14]) + W[i + ii + 9] + s0(W[i + ii + 1]) + W[i + ii]

static void
SHA512_Transform(uint64_t *state, const uint8_t block[128], uint64_t W[80],
                 uint64_t S[8])
{
    int i;

    be64dec_vect(W, block, 128);
    memcpy(S, state, 64);
    for (i = 0; i < 80; i += 16) {
        RNDr(S, W, 0, i);
        RNDr(S, W, 1, i);
        RNDr(S, W, 2, i);
        RNDr(S, W, 3, i);
        RNDr(S, W, 4, i);
        RNDr(S, W, 5, i);
        RNDr(S, W, 6, i);
        RNDr(S, W, 7, i);
        RNDr(S, W, 8, i);
        RNDr(S, W, 9, i);
        RNDr(S, W, 10, i);
        RNDr(S, W, 11, i);
        RNDr(S, W, 12, i);
        RNDr(S, W, 13, i);
        RNDr(S, W, 14, i);
        RNDr(S, W, 15, i);
        if (i == 64) {
            break;
        }
        MSCH(W, 0, i);
        MSCH(W, 1, i);
        MSCH(W, 2, i);
        MSCH(W, 3, i);
        MSCH(W, 4, i);
        MSCH(W, 5, i);
        MSCH(W, 6, i);
        MSCH(W, 7, i);
        MSCH(W, 8, i);
        MSCH(W, 9, i);
        MSCH(W, 10, i);
        MSCH(W, 11, i);
        MSCH(W, 12, i);
        MSCH(W, 13, i);
        MSCH(W, 14, i);
        MSCH(W, 15, i);
    }
    for (i = 0; i < 8; i++) {
        state[i] += S[i];
    }
}

static const uint8_t PAD[128] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void
SHA512_Pad(crypto_hash_sha512_state_tweet *state, uint64_t tmp64[80 + 8])
{
    unsigned int r;
    unsigned int i;

    r = (unsigned int) ((state->count[1] >> 3) & 0x7f);
    if (r < 112) {
        for (i = 0; i < 112 - r; i++) {
            state->buf[r + i] = PAD[i];
        }
    } else {
        for (i = 0; i < 128 - r; i++) {
            state->buf[r + i] = PAD[i];
        }
        SHA512_Transform(state->state, state->buf, &tmp64[0], &tmp64[80]);
        memset(&state->buf[0], 0, 112);
    }
    be64enc_vect(&state->buf[112], state->count, 16);
    SHA512_Transform(state->state, state->buf, &tmp64[0], &tmp64[80]);
}

int crypto_hash(u8 *out,const u8 *m,u64 n)
{
    crypto_hash_sha512_state_tweet hash_state;
    crypto_hash_sha512_init_tweet(&hash_state);
    crypto_hash_sha512_update_tweet(&hash_state, m, n);
    crypto_hash_sha512_final_tweet(&hash_state, out);
    return 0;
}

int
crypto_hash_sha512_init_tweet(crypto_hash_sha512_state_tweet *state)
{
    static const uint64_t sha512_initial_state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
        0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    state->count[0] = state->count[1] = (uint64_t) 0U;
    memcpy(state->state, sha512_initial_state, sizeof sha512_initial_state);

    return 0;
}

int
crypto_hash_sha512_update_tweet(crypto_hash_sha512_state_tweet *state,
                          const unsigned char *in, unsigned long long inlen)
{
    uint64_t           tmp64[80 + 8];
    uint64_t           bitlen[2];
    unsigned long long i;
    unsigned long long r;

    if (inlen <= 0U) {
        return 0;
    }
    r = (unsigned long long) ((state->count[1] >> 3) & 0x7f);

    bitlen[1] = ((uint64_t) inlen) << 3;
    bitlen[0] = ((uint64_t) inlen) >> 61;
    /* LCOV_EXCL_START */
    if ((state->count[1] += bitlen[1]) < bitlen[1]) {
        state->count[0]++;
    }
    /* LCOV_EXCL_STOP */
    state->count[0] += bitlen[0];
    if (inlen < 128 - r) {
        for (i = 0; i < inlen; i++) {
            state->buf[r + i] = in[i];
        }
        return 0;
    }
    for (i = 0; i < 128 - r; i++) {
        state->buf[r + i] = in[i];
    }
    SHA512_Transform(state->state, state->buf, &tmp64[0], &tmp64[80]);
    in += 128 - r;
    inlen -= 128 - r;

    while (inlen >= 128) {
        SHA512_Transform(state->state, in, &tmp64[0], &tmp64[80]);
        in += 128;
        inlen -= 128;
    }
    inlen &= 127;
    for (i = 0; i < inlen; i++) {
        state->buf[i] = in[i];
    }
    memset((void *) tmp64,0x00, sizeof tmp64);

    return 0;
}

int
crypto_hash_sha512_final_tweet(crypto_hash_sha512_state_tweet *state, unsigned char *out)
{
    uint64_t tmp64[80 + 8];

    SHA512_Pad(state, tmp64);
    be64enc_vect(out, state->state, 64);
    memset((void *) tmp64,0x00, sizeof tmp64);
    memset((void *) state,0x00, sizeof *state);

    return 0;
}
