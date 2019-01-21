int pi[0x3000];
int *compute_prefix_function(char *pattern, int psize)
{
	int k = -1;
	int i = 1;

	pi[0] = k;
	for (i = 1; i < psize; i++) {
		while (k > -1 && pattern[k+1] != pattern[i])
			k = pi[k];
		if (pattern[i] == pattern[k+1])
			k++;
		pi[i] = k;
	}
	return pi;
}

int kmp(char *target, int tsize, char *pattern, int psize)
{
	int i;
	int *pi = compute_prefix_function(pattern, psize);
	int k = -1;
	if (!pi)
		return -1;
	for (i = 0; i < tsize; i++) {
		while (k > -1 && pattern[k+1] != target[i])
			k = pi[k];
		if (target[i] == pattern[k+1])
			k++;
		if (k == psize - 1) {
			return i-k;
		}
	}

	return -1;
}
char* memmem(char *target, int tsize, char *pattern, int psize){
	int ans = kmp(target,tsize,pattern,psize);
	if(ans!=-1) return target+ans;
	else return (char*)0;
}

