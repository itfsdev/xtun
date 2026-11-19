#ifndef TEST_PROBE_CODES_H
#define TEST_PROBE_CODES_H

// Results of a connection probe, also used as exit codes of the xtun_split_probe program.
// A blocked connection is reported with the system error code instead, for example WSAEACCES.
namespace libxtun::test
{
    constexpr int CONNECTED_VIA_TUNNEL = 200;
    constexpr int CONNECTED_ELSEWHERE = 201;
}

#endif
