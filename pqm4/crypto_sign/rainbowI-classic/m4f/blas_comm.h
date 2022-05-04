/// @file blas_comm.h
/// @brief Common functions for linear algebra.
///
#ifndef _BLAS_COMM_H_
#define _BLAS_COMM_H_

#include <stdint.h>


/// @brief get an element from GF(16) vector .
///
/// @param[in]  a         - the input vector a.
/// @param[in]  i         - the index in the vector a.
/// @return  the value of the element.
///
static inline uint8_t gf16v_get_ele(const uint8_t *a, unsigned i) {
    uint8_t r = a[i >> 1];
    uint8_t r0 = r&0xf;
    uint8_t r1 = r>>4;
    uint8_t m = (uint8_t)(-(i&1));
    return (r1&m)|((~m)&r0);
}

/// @brief set an element for a GF(16) vector .
///
/// @param[in,out]   a   - the vector a.
/// @param[in]  i        - the index in the vector a.
/// @param[in]  v        - the value for the i-th element in vector a.
/// @return  the value of the element.
///
static inline uint8_t gf16v_set_ele(uint8_t *a, unsigned i, uint8_t v) {
    uint8_t m = 0xf ^ (-(i&1));   ///  1--> 0xf0 , 0--> 0x0f
    uint8_t ai_remaining = a[i>>1] & (~m);   /// erase
    a[i>>1] = ai_remaining | (m&(v<<4))|(m&v&0xf);  /// set
    return v;
}


/// @brief get an element from GF(256) vector .
///
/// @param[in]  a         - the input vector a.
/// @param[in]  i         - the index in the vector a.
/// @return  the value of the element.
///
static inline uint8_t gf256v_get_ele(const uint8_t *a, unsigned i) { return a[i]; }


/// @brief set an element for a GF(256) vector .
///
/// @param[in,out]   a   - the vector a.
/// @param[in]  i        - the index in the vector a.
/// @param[in]  v        - the value for the i-th element in vector a.
/// @return  the value of the element.
///
static inline uint8_t gf256v_set_ele(uint8_t *a, unsigned i, uint8_t v) { a[i]=v; return v; }


#ifdef  __cplusplus
extern  "C" {
#endif


/////////////////////////////////////


/// @brief set a vector to 0.
///
/// @param[in,out]   b      - the vector b.
/// @param[in]  _num_byte   - number of bytes for the vector b.
///
void gf256v_set_zero(uint8_t *b, unsigned _num_byte);


/// @brief check if a vector is 0.
///
/// @param[in]   a          - the vector a.
/// @param[in]  _num_byte   - number of bytes for the vector a.
/// @return  1(true) if a is 0. 0(false) else.
///
unsigned gf256v_is_zero(const uint8_t *a, unsigned _num_byte);



///////////////// Section: multiplications  ////////////////////////////////


/// @brief polynomial multiplication:  c = a*b
///
/// @param[out]   c         - the output polynomial c
/// @param[in]   a          - the vector a.
/// @param[in]   b          - the vector b.
/// @param[in]  _num   - number of elements for the polynomials a and b.
///
void gf256v_polymul(uint8_t *c, const uint8_t *a, const uint8_t *b, unsigned _num);


/// @brief matrix-vector multiplication:  c = matA * b , in GF(16)
///
/// @param[out]  c         - the output vector c
/// @param[in]   matA      - a column-major matrix A.
/// @param[in]   n_A_vec_byte  - the size of column vectors in bytes.
/// @param[in]   n_A_width   - the width of matrix A.
/// @param[in]   b          - the vector b.
///
void gf16mat_prod(uint8_t *c, const uint8_t *matA, unsigned n_A_vec_byte, unsigned n_A_width, const uint8_t *b);


/// @brief matrix-vector multiplication:  c = matA * b , in GF(256)
///
/// @param[out]  c         - the output vector c
/// @param[in]   matA      - a column-major matrix A.
/// @param[in]   n_A_vec_byte  - the size of column vectors in bytes.
/// @param[in]   n_A_width   - the width of matrix A.
/// @param[in]   b          - the vector b.
///
void gf256mat_prod(uint8_t *c, const uint8_t *matA, unsigned n_A_vec_byte, unsigned n_A_width, const uint8_t *b);


/// @brief matrix-matrix multiplication:  c = a * b , in GF(16)
///
/// @param[out]  c         - the output matrix c
/// @param[in]   c         - a matrix a.
/// @param[in]   b         - a matrix b.
/// @param[in]   len_vec   - the length of column vectors.
///
void gf16mat_mul(uint8_t *c, const uint8_t *a, const uint8_t *b, unsigned len_vec);


/// @brief matrix-matrix multiplication:  c = a * b , in GF(256)
///
/// @param[out]  c         - the output matrix c
/// @param[in]   c         - a matrix a.
/// @param[in]   b         - a matrix b.
/// @param[in]   len_vec   - the length of column vectors.
///
void gf256mat_mul(uint8_t *c, const uint8_t *a, const uint8_t *b, unsigned len_vec);




/////////////////   algorithms:  gaussian elim  //////////////////


/// @brief Gauss elimination for a matrix, in GF(16)
///
/// @param[in,out]  mat    - the matrix.
/// @param[in]   h         - the height of the matrix.
/// @param[in]   w         - the width of the matrix.
/// @return   1(true) if success. 0(false) if the matrix is singular.
///
unsigned gf16mat_gauss_elim(uint8_t *mat, unsigned h, unsigned w);

/// @brief Solving linear equations, in GF(16)
///
/// @param[out]  sol       - the solutions.
/// @param[in]   inp_mat   - the matrix parts of input equations.
/// @param[in]   c_terms   - the constant terms of the input equations.
/// @param[in]   n         - the number of equations.
/// @return   1(true) if success. 0(false) if the matrix is singular.
///
unsigned gf16mat_solve_linear_eq(uint8_t *sol, const uint8_t *inp_mat, const uint8_t *c_terms, unsigned n);


/// @brief Gauss elimination for a matrix, in GF(256)
///
/// @param[in,out]  mat    - the matrix.
/// @param[in]   h         - the height of the matrix.
/// @param[in]   w         - the width of the matrix.
/// @return   1(true) if success. 0(false) if the matrix is singular.
///
unsigned gf256mat_gauss_elim(uint8_t *mat, unsigned h, unsigned w);

/// @brief Solving linear equations, in GF(256)
///
/// @param[out]  sol       - the solutions.
/// @param[in]   inp_mat   - the matrix parts of input equations.
/// @param[in]   c_terms   - the constant terms of the input equations.
/// @param[in]   n         - the number of equations.
/// @return   1(true) if success. 0(false) if the matrix is singular.
///
unsigned gf256mat_solve_linear_eq(uint8_t *sol, const uint8_t *inp_mat, const uint8_t *c_terms, unsigned n);



////////////////  Section: inversion for matrices   //////////////////////////


/// @brief Computing the inverse matrix, in GF(16)
///
/// @param[out]  inv_a     - the output of matrix a.
/// @param[in]   a         - a matrix a.
/// @param[in]   H         - height of matrix a, i.e., matrix a is an HxH matrix.
/// @param[in]   buffer    - The buffer for computations. it has to be as large as 2 input matrixes.
/// @return   1(true) if success. 0(false) if the matrix is singular.
///
unsigned gf16mat_inv(uint8_t *inv_a, const uint8_t *a, unsigned H, uint8_t *buffer);


/// @brief Computing the inverse matrix, in GF(256)
///
/// @param[out]  inv_a     - the output of matrix a.
/// @param[in]   a         - a matrix a.
/// @param[in]   H         - height of matrix a, i.e., matrix a is an HxH matrix.
/// @param[in]   buffer    - The buffer for computations. it has to be as large as 2 input matrixes.
/// @return   1(true) if success. 0(false) if the matrix is singular.
///
unsigned gf256mat_inv(uint8_t *inv_a, const uint8_t *a, unsigned H, uint8_t *buffer);


#ifdef  __cplusplus
}
#endif

#endif  // _BLAS_COMM_H_

