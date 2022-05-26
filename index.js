const Fastify = require('fastify')
const axios = require('axios')
const yaml = require('js-yaml')
const {JSON_SCHEMA} = require("js-yaml");
const fastify = Fastify({
    logger: true
})

fastify.get('/clash', async (request, reply) => {
    const url = request.query.url
    const mixinUrl = request.query.mixin
    console.log('url', url)
    console.log('mixinUrl', mixinUrl)
    const sourceRet = await axios.get(url)
    const sourceJson = yaml.load(sourceRet.data)
    const mixinRet = await axios.get(mixinUrl)
    const mixinJson = yaml.load(mixinRet.data)
    const mixinProxyNames = []
    if (mixinJson.proxies) {
        sourceJson.proxies.push(...mixinJson.proxies)
        mixinProxyNames.push(...mixinJson.proxies.map(proxy => proxy.name))
    }
    const sourceProxyNames = sourceJson.proxies.map(proxy => proxy.name)
    const removedProxyGroups = []
    if (mixinJson['proxy-groups']) {
        for (const proxyGroup of mixinJson['proxy-groups']) {
            if (!proxyGroup.proxies) {
                proxyGroup.proxies = []
            }
            if (proxyGroup.type === 'url-test') {
                const pattern = proxyGroup.name.replace(/^\s*Auto - /, '')
                proxyGroup.proxies.push(...sourceProxyNames.filter(name => name.match(pattern)))
            } else {
                proxyGroup.proxies.push(...sourceProxyNames)
            }
            if (proxyGroup.proxies && proxyGroup.proxies.length > 0) {
                sourceJson['proxy-groups'].push(proxyGroup)
            } else {
                removedProxyGroups.push(proxyGroup.name.trim());
            }
        }
    }
    if (removedProxyGroups.length > 0) {
        sourceJson['proxy-groups'] = sourceJson['proxy-groups'].map(proxyGroup => {
            return {
                ...proxyGroup,
                proxies: proxyGroup.proxies.filter(proxy => !removedProxyGroups.includes(proxy.trim()))
            }
        })
    }
    const autoProxyGroupNames = mixinJson['proxy-groups']?.filter(group => group.type === 'url-test' && !removedProxyGroups.includes(group.name)).map(group => group.name) ?? []

    if (autoProxyGroupNames.length > 0) {
        sourceJson['proxy-groups'].forEach((group, index) => {
            if (group.type !== 'select') {
                return
            }
            sourceJson['proxy-groups'][index].proxies.push(...autoProxyGroupNames)
        })
    }
    if (mixinJson['rules']) {
        sourceJson.rules.unshift(...mixinJson['rules'])
    }
    if (mixinJson['rule-providers']) {
        Object.assign(sourceJson['rule-providers'], mixinJson['rule-providers'])
    }
    let ruleSetStringArr = JSON.stringify(Object.fromEntries(sourceJson.rules.filter(rule => rule.startsWith('RULE-SET,')).map(rule => {
        const matched = rule.split(',')
        return [matched[1], matched[2]]
    })), null, 8).split('\n')
    ruleSetStringArr[ruleSetStringArr.length - 1] = `   ${ruleSetStringArr[ruleSetStringArr.length - 1]}`
    sourceJson.script.code = `
def main(ctx, metadata):
    ruleset_action = ${ruleSetStringArr.join('\n')}
    
    port = int(metadata["dst_port"])

    if metadata["network"] == "UDP":
        if port == 443:
            ctx.log('[Script] matched QUIC traffic use reject')
            return "REJECT"

    port_list = [21, 22, 23, 53, 80, 123, 143, 194, 443, 465, 587, 853, 993, 995, 998, 2052, 2053, 2082, 2083, 2086, 2095, 2096, 5222, 5228, 5229, 5230, 8080, 8443, 8880, 8888, 8889]
    if port not in port_list:
        ctx.log('[Script] not common port use direct')
        return "DIRECT"

    if metadata["dst_ip"] == "":
        metadata["dst_ip"] = ctx.resolve_ip(metadata["host"])

    for ruleset in ruleset_action:
        if ctx.rule_providers[ruleset].match(metadata):
            return ruleset_action[ruleset]

    if metadata["dst_ip"] == "":
        return "DIRECT"

    code = ctx.geoip(metadata["dst_ip"])
    if code == "CN":
        ctx.log('[Script] Geoip CN')
        return "Domestic"

    ctx.log('[Script] FINAL')
    return "Others"
    `
    // reply.send(sourceJson)
    if (sourceRet.headers['profile-update-interval']) {
        reply.header('profile-update-interval', sourceRet.headers['profile-update-interval'])
    }
    if (sourceRet.headers['subscription-userinfo']) {
        reply.header('subscription-userinfo', sourceRet.headers['subscription-userinfo'])
    }

    reply.send('---\n' + yaml.dump(sourceJson))
})


// Run the server!
fastify.listen(process.env.PORT || 3000, '0.0.0.0', (err, address) => {
    if (err) throw err
    // Server is now listening on ${address}
})
