/*
 * Copyright 2020. Heekuck Oh, all rights reserved
 * 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었습니다.
 * 2016003818_컴퓨터공학과_이준기
 */
#include <stdlib.h>
#include "mRSA.h"

// pr4
uint64_t mod_add(uint64_t a, uint64_t b, uint64_t m)
{
    a = a % m; // a mod m
    b = b % m; // b mod m

    if ((a+b) < b) { // Overflow 확인
        return (a + (b - m)) % m;
    }
    return (a + b) % m;
}

// pr4
uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t m)
{
    uint64_t r = 0;
    while (b > 0) {
        if (b & 1) {
            r = mod_add(r, a, m);
        }
        b = b >> 1;
        a = mod_add(a, a, m);
    }
    return r;
}

// pr4
uint64_t mod_pow(uint64_t a, uint64_t b, uint64_t m)
{
    uint64_t r = 1;
    while (b > 0) {
        if (b & 1) {
            r = mod_mul(r, a, m);
        }
        b = b >> 1;
        a = mod_mul(a, a, m);
    }
    return r;
}

// pr4
static int miller_rabin(uint64_t n)
{
	uint64_t det[12] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}; // Deterministic 값
	uint64_t i, j; // 반복문용 변수
	uint64_t k = 0, q = 1;
	
	// k, q를 찾는다.
	uint64_t tmp = n-1;
	while (1) {
		if ((tmp % 2) != 0) { // n-1이 2로 나누어떨어지지 않으면 2^k만큼 나눈 것이니
			q = tmp; // 남은 값인 q를 저장하고 나온다.
			break;
		}
		tmp /= 2;
		k++; // k를 자동으로 저장한다.
	}

	// Deterministic 하게 하기 위해 12개의 원소 만큼 반복
	for (i = 0; i < 12; i++) {
		if (det[i] >= n-1) { // 1 < a < n-1가 만족되지 못한 경우 반복문 종료
			break;
		}
		
        // a^q mod n이 1인 경우 inconclusive
		tmp = mod_pow(det[i], q, n); 
		if (tmp == 1) {
			continue;
		}
		
		// (a^q) 계산
		tmp = mod_pow(det[i], q, n);
    	j = 0;
    	uint64_t r = 1;
		
        // (a^q)^(2^j) 연산 시간을 줄이기 위해 square multiplication 방식을 채택
		while(j < k) {
			if (j == 0){ // j = 0 일 경우 계산
				r = mod_mul(tmp, r, n);
			}
	        if (r == n - 1) { // (a^q)^(2^j) mod n 이 n-1이면 inconclusive
	        	break;
			}
	        r = mod_mul(r, r, n); // square multiplication
	        j++;
		}
		
		if (j == k) { // j == k 이면 위의 반목문을 통과한 것이므로 Composite
			return COMPOSITE;
		}
	}
	return PRIME;
}

// pr1
uint64_t gcd(uint64_t a, uint64_t b)
{
	while(b != 0) {
		uint64_t tmp = a;
		a = b;
		b = tmp % b;
	}
	return a;
}

// lambda
uint64_t lambda(uint64_t p, uint64_t q)
{
	uint64_t pi = (p-1) * (q-1);
	uint64_t gc = gcd(p-1, q-1);
	return pi / gc; // lambda(n) = (p-1)(q-1) / gcd(p-1, q-1)
}

// pr1 에서 가져와 uint64_t 타입에 맞게 수정
uint64_t mul_inv(uint64_t a, uint64_t m)
{
	uint64_t d0 = a;
    uint64_t d1 = m;
    uint64_t x0 = 1;
    uint64_t x1 = 0;
    uint64_t q;
    uint64_t tmp;
    uint64_t count = 0; // 음수 양수 구분을 위한 홀짝 구분용 카운트

    while (d1 > 1) {
        q = d0 / d1;
        tmp = d0 - q * d1;
        d0 = d1;
        d1 = tmp;
		tmp = x0 + q * x1;
        x0 = x1;
        x1 = tmp;
        count++; // 카운트 증가
    }
    if (count % 2 == 0) { // 짝수번째로 끝나면 음수이므로 양수로 수정
        x1 = m - x1;
    }
    if (d1 == 1) { 
        return (x1 > 0 ? x1:x1+m);
    } else {
        return 0;
    }
}

/*
 * mRSA_generate_key() - generates mini RSA keys e, d and n
 * Carmichael's totient function Lambda(n) is used.
 */
void mRSA_generate_key(uint64_t *e, uint64_t *d, uint64_t *n)
{
    uint64_t p = 0; // uint32_t 값을 받아 써서 초기화를 안하면 
	uint64_t q = 0; // 더미값에 의한 문제가 생기므로 0으로 초기화.

	while (1) { // n의 숫자의 크기가 보장되기 위해 반복문을 수행
		while(1) { // 소수 p 생성
			arc4random_buf(&p, sizeof(uint32_t)); // 32bit 난수를 받아옴
			if(miller_rabin(p)) { // 받아온 수가 소수인지 검증
				break;
			}
		}

		while(1) { // 소수 q 생성
			arc4random_buf(&q, sizeof(uint32_t)); // 32bit 난수를 받아옴
			if(miller_rabin(q)) { // 받아온 수가 소수인지 검증
				break;
			}
		}

		*n = p * q; // 모듈러 n 계산
		if ((*n>>63) & 1) { // n >= 2^63이 만족되면 반복문을 탈출
			break;
		}
	}
	
	uint64_t lam = lambda(p, q); // 작성 편의를 위한 lambda(n) 계산

	while(1) { // e Calculate
		arc4random_buf(e, sizeof(uint64_t)); // 랜덤한 64bit 숫자 e를 생성
		if (1 < *e && *e < lam && gcd(*e, lam) == 1) { // e가 RSA 키에 적합한지 검사
			break;
		}
	}

	*d = mul_inv(*e, lam); // ed == 1 mod lambda(n)을 만족시킬 d를 계산
}

/*
 * mRSA_cipher() - compute m^k mod n
 * If data >= n then returns 1 (error), otherwise 0 (success).
 */
int mRSA_cipher(uint64_t *m, uint64_t k, uint64_t n)
{	
	if (*m >= n) { // 메시지가 n보다 크면 에러
		return -1;
	}
    *m = mod_pow(*m, k, n); // 지수 연산
	return 0;
}