#include "B2A.h"

/*
-------------------------------------------
       Higher order masking functions
-------------------------------------------
*/
// taken from https://eprint.iacr.org/2018/328.pdf (https://pastebin.com/WKnNyEU8)
//  This program is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License version 2 as published
//  by the Free Software Foundation.

static void refresh(uint16_t a[],int n)
{
  int i;
  uint32_t rand;
  uint16_t tmp,tmp1;
  
  if((n%2)==0)
  {
      for(i=1;i<(n/2);i++)
    {
      rand = random_uint32();
      tmp=(rand & 0xffff);
      tmp1=((rand>>16) & 0xffff);
      a[0]=(a[0] ^ tmp)^tmp1;
      a[2*i]=a[2*i] ^ tmp;
      a[2*i+1]=a[2*i+1] ^ tmp1;
    }
  }
  else
  {
      for(i=1;i<(n/2);i++)
    {
      rand = random_uint32();
      tmp=(rand & 0xffff);
      tmp1=((rand>>16) & 0xffff);
      a[0]=(a[0] ^ tmp)^tmp1;
      a[2*i]=a[2*i] ^ tmp;
      a[2*i+1]=a[2*i+1] ^ tmp1;
    }
    rand = random_uint32();
    tmp=(rand & 0xffff);
    a[0]=a[0] ^ tmp;
    a[n-1]=a[n-1] ^ tmp;
  }
   
}


static uint16_t Psi(uint16_t x,uint16_t y)
{
  return (x ^ y)-y;
}

static uint16_t Psi0(uint16_t x,uint16_t y,int n)
{
  return Psi(x,y) ^ ((~n & 1) * x);
}

void copy(uint16_t *x,uint16_t *y,int n)
{
  for(int i=0;i<n;i++) x[i]=y[i];
}

static void impconvBA_rec(uint16_t *D,uint16_t *x,int n);

void impconvBA(uint16_t *D,uint16_t *x,int n)
{
  uint16_t x_ext[n+1];
  copy(x_ext,x,n);
  x_ext[n] = 0;
  impconvBA_rec(D, x_ext, n);
}

// here, x contains n+1 shares
static void impconvBA_rec(uint16_t *D,uint16_t *x,int n)
{  
  uint32_t rand;
  if (n==2)
  {
    rand = random_uint32();
    uint16_t r1=rand&0xffff;
    uint16_t r2=(rand>>16)&0xffff;
    uint16_t y0=(x[0] ^ r1) ^ r2;
    uint16_t y1=x[1] ^ r1;
    uint16_t y2=x[2] ^ r2;
    
    uint16_t z0=y0 ^ Psi(y0,y1);
    uint16_t z1=Psi(y0,y2);
    
    D[0]=y1 ^ y2;
    D[1]=z0 ^ z1;
    return;
  }

  uint16_t y[n+1];
  copy(y,x,n+1);

  refresh(y,n+1);

  uint16_t z[n];

  z[0]=Psi0(y[0],y[1],n);
  for(int i=1;i<n;i++)
    z[i]=Psi(y[0],y[i+1]);

  uint16_t A[n-1],B[n-1];
  impconvBA_rec(A,y+1,n-1);
  impconvBA_rec(B,z,n-1);
  
  for(int i=0;i<n-2;i++)
    D[i]=A[i]+B[i];

  D[n-2]=A[n-2];
  D[n-1]=B[n-2];

}

static void refresh_32(uint32_t a[],int n)
{
  int i;
  uint32_t rand;
  uint32_t tmp;
  for(i=1;i<n;i++)
  {
    rand = random_uint32();
    tmp=rand;
    a[0]=a[0] ^ tmp;
    a[i]=a[i] ^ tmp;
  }
}


static uint32_t Psi_32(uint32_t x,uint32_t y)
{
  return (x ^ y)-y;
}

static uint32_t Psi0_32(uint32_t x,uint32_t y,int n)
{
  return Psi_32(x,y) ^ ((~n & 1) * x);
}

void copy_32(uint32_t *x,uint32_t *y,int n)
{
  for(int i=0;i<n;i++) x[i]=y[i];
}

static void impconvBA_rec_32(uint32_t *D,uint32_t *x,int n);

void impconvBA_32(uint32_t *D,uint32_t *x,int n)
{
  uint32_t x_ext[n+1];
  copy_32(x_ext,x,n);
  x_ext[n] = 0;
  impconvBA_rec_32(D, x_ext, n);
}

// here, x contains n+1 shares
static void impconvBA_rec_32(uint32_t *D,uint32_t *x,int n)
{ 
  uint32_t rand[2]; 
  if (n==2)
  {
    rand[0] = random_uint32();
    rand[1] = random_uint32();
    uint32_t r1=rand[0];
    uint32_t r2=rand[1];
    uint32_t y0=(x[0] ^ r1) ^ r2;
    uint32_t y1=x[1] ^ r1;
    uint32_t y2=x[2] ^ r2;
    
    uint32_t z0=y0 ^ Psi_32(y0,y1);
    uint32_t z1=Psi_32(y0,y2);
    
    D[0]=y1 ^ y2;
    D[1]=z0 ^ z1;
    return;
  }

  uint32_t y[n+1];
  copy_32(y,x,n+1);

  refresh_32(y,n+1);

  uint32_t z[n];

  z[0]=Psi0_32(y[0],y[1],n);
  for(int i=1;i<n;i++)
    z[i]=Psi_32(y[0],y[i+1]);

  uint32_t A[n-1],B[n-1];
  impconvBA_rec_32(A,y+1,n-1);
  impconvBA_rec_32(B,z,n-1);
  
  for(int i=0;i<n-2;i++)
    D[i]=A[i]+B[i];

  D[n-2]=A[n-2];
  D[n-1]=B[n-2];

}
